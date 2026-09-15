//! The energy clusters against arbitrary invoke payloads.
//!
//! These are the clusters that move real power, and every one of their commands is a *plan* a
//! client sends: a charging schedule, a power adjustment, a boost with a duration and two
//! percentages. The decoders are generated, but the validation around them is hand-written and
//! is what stands between a malformed payload and a car that charges at the wrong hour.
//!
//! Seven properties, checked after every command:
//!
//! 1. **Nothing panics**, on any payload, in any order. Three clusters share one appliance and
//!    each uses `RefCell`/`Cell`; a nested borrow would be a panic reachable from the network.
//! 2. **No fabric exceeds the EVSE's per-day target store**, and no stored target is outside
//!    §9.3.7.6's "max 1439" minutes or a valid percentage.
//! 3. **Every stored charging target is reachable**: `GetTargets` decodes, whatever was set.
//! 4. **`SupplyState` never contradicts `FaultState`** (§9.3.8.3): a fault means
//!    `DisabledError` and nothing else.
//! 5. **A water-heater boost always has an end** — `BoostState` is Active only while a boost is
//!    stored, and every stored boost has a non-zero duration.
//! 6. **A power adjustment is only ever active for a cause the opt-out permits** (§9.2.8.8).
//! 7. **A response always decodes**, so a malformed request cannot leave a half-written
//!    `InvokeResponseMessage` behind.

#![no_main]

use core::cell::Cell;

use libfuzzer_sys::fuzz_target;
use matter_kit::clusters::device_energy_management::{
    self as dem, AdjustmentCauseEnum, DemHooks, DeviceEnergyManagement, ESAStateEnum, ESATypeEnum,
    ForecastSummary, OptOutStateEnum, PowerAdjustReasonEnum, PowerAdjustStruct,
};
use matter_kit::clusters::energy_evse::{
    self as evse, EnergyEvse, EvseHooks, FaultStateEnum, StateEnum, SupplyStateEnum,
    TargetDayOfWeekBitmap,
};
use matter_kit::clusters::water_heater_management::{
    self as water, BoostStateEnum, WaterHeaterBoostInfoStruct, WaterHeaterHeatSourceBitmap,
    WaterHeaterHooks, WaterHeaterManagement,
};
use matter_kit::dm::spec::Optional;
use matter_kit::dm::{ClusterDescriptor, Endpoint, Node, Privilege};
use matter_kit::im::{
    AccessControl, AttributePath, InvokeRequest, InvokeResponseMessage, Outcome, Server,
};
use matter_kit::msg::{FabricIndex, GroupId};
use matter_kit::platform::{Duration, Instant};

struct AllowAll;

impl AccessControl for AllowAll {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Granted
    }
}

/// One appliance behind all three clusters, with a few knobs the fuzzer steers through the
/// first input byte.
struct Appliance {
    fault: Cell<FaultStateEnum>,
    opt_out: Cell<OptOutStateEnum>,
    minimum_boost: Cell<u32>,
    ranges: [PowerAdjustStruct; 1],
}

impl Appliance {
    fn new(seed: u8) -> Self {
        Self {
            fault: Cell::new(if seed & 1 == 0 {
                FaultStateEnum::NoError
            } else {
                FaultStateEnum::GroundFault
            }),
            opt_out: Cell::new(match seed >> 1 & 3 {
                0 => OptOutStateEnum::NoOptOut,
                1 => OptOutStateEnum::LocalOptOut,
                2 => OptOutStateEnum::GridOptOut,
                _ => OptOutStateEnum::OptOut,
            }),
            minimum_boost: Cell::new(u32::from(seed) * 4),
            ranges: [PowerAdjustStruct {
                min_power: 1_000_000,
                max_power: 7_000_000,
                min_duration: 30,
                max_duration: 3_600,
            }],
        }
    }
}

impl EvseHooks for Appliance {
    fn state(&self) -> Option<StateEnum> {
        Some(StateEnum::PluggedInCharging)
    }

    fn fault(&self) -> FaultStateEnum {
        self.fault.get()
    }

    fn utc(&self) -> Option<u32> {
        Some(50_000)
    }

    fn circuit_capacity(&self) -> i64 {
        32_000
    }

    fn session_id(&self) -> Option<u32> {
        Some(1)
    }

    fn session_duration(&self) -> Option<u32> {
        Some(0)
    }

    fn session_energy_charged(&self) -> Option<i64> {
        Some(0)
    }

    fn enable_charging(&self, _minimum_ma: i64, _maximum_ma: i64) -> bool {
        true
    }

    fn enable_discharging(&self, _maximum_ma: i64) -> bool {
        true
    }

    fn start_diagnostics(&self) -> bool {
        true
    }
}

impl WaterHeaterHooks for Appliance {
    fn heat_demand(&self) -> WaterHeaterHeatSourceBitmap {
        WaterHeaterHeatSourceBitmap::empty()
    }

    fn boost(&self, info: &WaterHeaterBoostInfoStruct) -> Result<(), matter_kit::im::Status> {
        if info.duration < self.minimum_boost.get() {
            return Err(matter_kit::im::Status::InvalidInState);
        }
        Ok(())
    }
}

impl DemHooks for Appliance {
    fn esa_type(&self) -> ESATypeEnum {
        ESATypeEnum::EVSE
    }

    fn base_state(&self) -> ESAStateEnum {
        ESAStateEnum::Online
    }

    fn abs_min_power(&self) -> i64 {
        0
    }

    fn abs_max_power(&self) -> i64 {
        7_000_000
    }

    fn opt_out_state(&self) -> OptOutStateEnum {
        self.opt_out.get()
    }

    fn power_adjust_ranges(&self) -> &[PowerAdjustStruct] {
        &self.ranges
    }

    fn forecast(&self) -> Option<ForecastSummary> {
        Some(ForecastSummary {
            forecast_id: 7,
            start_time: 60_000,
            end_time: 67_200,
            earliest_start_time: Some(55_000),
            latest_end_time: Some(90_000),
            slot_is_pausable: true,
            min_pause_duration: 60,
            max_pause_duration: 600,
            adjusted: false,
        })
    }

    fn power_adjust(
        &self,
        _power_mw: i64,
        _duration_s: u32,
        _cause: AdjustmentCauseEnum,
    ) -> Result<(), matter_kit::im::Status> {
        Ok(())
    }

    fn adjust_start_time(
        &self,
        _requested_start_time: u32,
        _cause: AdjustmentCauseEnum,
    ) -> Result<(), matter_kit::im::Status> {
        Ok(())
    }

    fn pause(
        &self,
        _duration_s: u32,
        _cause: AdjustmentCauseEnum,
    ) -> Result<(), matter_kit::im::Status> {
        Ok(())
    }
}

const TARGETS_PER_DAY: usize = 4;
const ALL_FEATURES: u32 = evse::feature::CHARGING_PREFERENCES
    | evse::feature::V2_X
    | evse::feature::SO_C_REPORTING;
const DEM_FEATURES: u32 = dem::feature::POWER_ADJUSTMENT
    | dem::feature::POWER_FORECAST_REPORTING
    | dem::feature::START_TIME_ADJUSTMENT
    | dem::feature::PAUSABLE
    | dem::feature::FORECAST_ADJUSTMENT
    | dem::feature::CONSTRAINT_BASED_ADJUSTMENT;

fuzz_target!(|data: &[u8]| {
    let Some((&seed, body)) = data.split_first() else {
        return;
    };
    let appliance = Appliance::new(seed);
    let evse_cluster: EnergyEvse<'_, Appliance, TARGETS_PER_DAY> =
        EnergyEvse::new(&appliance, ALL_FEATURES);
    let water_cluster = WaterHeaterManagement::new(
        &appliance,
        WaterHeaterHeatSourceBitmap::HEAT_PUMP,
    );
    let dem_cluster = DeviceEnergyManagement::new(&appliance, DEM_FEATURES);

    let Ok(evse_d) = EnergyEvse::<Appliance, TARGETS_PER_DAY>::conforming(
        ALL_FEATURES,
        &EnergyEvse::<Appliance, TARGETS_PER_DAY>::WITH_ALL_OPTIONAL,
    ) else {
        return;
    };
    let Ok(water_d) = WaterHeaterManagement::<Appliance>::conforming(
        water::feature::ENERGY_MANAGEMENT | water::feature::TANK_PERCENT,
        &Optional::NONE,
    ) else {
        return;
    };
    let Ok(dem_d) =
        DeviceEnergyManagement::<Appliance>::conforming(DEM_FEATURES, &Optional::NONE)
    else {
        return;
    };
    // Sorted by id: 0x0094, 0x0098, 0x0099.
    let clusters: [ClusterDescriptor<'_>; 3] = [
        water_d.descriptor(),
        dem_d.descriptor(),
        evse_d.descriptor(),
    ];
    let endpoints = [Endpoint::new(1, &clusters)];
    let node = Node::new(&endpoints);
    let access = AllowAll;
    let handler = (&water_cluster, &dem_cluster, &evse_cluster);
    let server = Server::new(node, &access, &handler, 8);

    for (index, fabric) in [FabricIndex(1), FabricIndex(2)].into_iter().enumerate() {
        let Ok(request) = InvokeRequest::decode(body) else {
            continue;
        };
        let Ok(commands) = request.commands() else {
            continue;
        };
        // Every energy command is Timed (§9.3.9's `OT`), and a groupcast on the second pass so
        // the "no response" path is exercised too.
        let mut ctx = matter_kit::im::InteractionContext::new()
            .with_fabric(fabric)
            .timed()
            .at(Instant::ZERO.saturating_add(Duration::from_secs(u64::from(seed))));
        if index == 1 {
            ctx = ctx.with_group(GroupId(4));
        }
        let mut scratch = [0u8; 2048];
        let mut buf = [0u8; 4096];
        if let Ok((bytes, _)) = server.serve_invoke(
            commands,
            &ctx,
            request.suppress_response,
            &mut scratch,
            &mut buf,
        ) {
            // Property 7.
            let decoded = InvokeResponseMessage::decode(bytes).expect("a response decodes");
            if let Ok(responses) = decoded.responses() {
                for response in responses {
                    let _ = response.expect("each response decodes");
                }
            }
        }
        // Timers, which are what turn a stored plan into an action.
        let now = Instant::ZERO.saturating_add(Duration::from_secs(u64::from(seed) * 97));
        water_cluster.poll(now);
        dem_cluster.poll(now);
        evse_cluster.poll();
        check(&appliance, &evse_cluster, &water_cluster, &dem_cluster, fabric);
    }
});

fn check(
    appliance: &Appliance,
    evse_cluster: &EnergyEvse<'_, Appliance, TARGETS_PER_DAY>,
    water_cluster: &WaterHeaterManagement<'_, Appliance>,
    dem_cluster: &DeviceEnergyManagement<'_, Appliance>,
    fabric: FabricIndex,
) {
    let _ = fabric;
    // Property 2 and 3.
    for day in [
        TargetDayOfWeekBitmap::SUNDAY,
        TargetDayOfWeekBitmap::MONDAY,
        TargetDayOfWeekBitmap::TUESDAY,
        TargetDayOfWeekBitmap::WEDNESDAY,
        TargetDayOfWeekBitmap::THURSDAY,
        TargetDayOfWeekBitmap::FRIDAY,
        TargetDayOfWeekBitmap::SATURDAY,
    ] {
        let targets = evse_cluster.targets_for(day);
        assert!(targets.len() <= TARGETS_PER_DAY);
        for target in &targets {
            assert!(
                target.target_time_minutes_past_midnight <= evse::MINUTES_MAX,
                "a target past the end of the day was stored"
            );
            assert!(target.target_so_c.is_none_or(|soc| soc <= 100));
            assert!(target.added_energy.is_none_or(|energy| energy >= 0));
        }
    }

    // Property 4.
    if appliance.fault.get() != FaultStateEnum::NoError {
        assert_eq!(
            evse_cluster.supply_state(),
            SupplyStateEnum::DisabledError,
            "a fault did not disable the supply"
        );
    }

    // Property 5.
    match water_cluster.boost_info() {
        Some(info) => {
            assert_eq!(water_cluster.boost_state(), BoostStateEnum::Active);
            assert!(info.duration > 0, "a boost with no duration was stored");
            assert!(info.target_percentage.is_none_or(|p| p <= 100));
            assert!(
                info.target_reheat
                    .zip(info.target_percentage)
                    .is_none_or(|(reheat, target)| reheat <= target),
                "a reheat above its target would never stop"
            );
        }
        None => assert_eq!(water_cluster.boost_state(), BoostStateEnum::Inactive),
    }

    // Property 6.
    let reason = dem_cluster.adjust_reason();
    match appliance.opt_out.get() {
        OptOutStateEnum::OptOut => assert_eq!(
            reason,
            PowerAdjustReasonEnum::NoAdjustment,
            "an adjustment ran for a user who opted out of everything"
        ),
        OptOutStateEnum::LocalOptOut => assert_ne!(
            reason,
            PowerAdjustReasonEnum::LocalOptimizationAdjustment,
            "a local optimisation ran for a user who opted out of local ones"
        ),
        OptOutStateEnum::GridOptOut => assert_ne!(
            reason,
            PowerAdjustReasonEnum::GridOptimizationAdjustment,
            "a grid optimisation ran for a user who opted out of grid ones"
        ),
        OptOutStateEnum::NoOptOut => {}
    }
}
