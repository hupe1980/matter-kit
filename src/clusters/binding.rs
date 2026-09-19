//! Binding, cluster `0x001E` (Core §9.6).
//!
//! A binding is "a persistent relationship between an endpoint and one or more other local or
//! remote endpoints" — how a switch is told which bulbs it controls. The cluster lives on the
//! **client** endpoint, and §9.6 is careful that it only records an intention:
//!
//! > A binding does not require that the relationship exists. It is up to the node
//! > application to set up the relationship.
//!
//! So this stores and validates the table; acting on it — opening a CASE session to the
//! target, sending the command — is the application's.
//!
//! # The three fields are mutually exclusive in a way that matters
//!
//! §9.6.5.1's `TargetStruct` has `Node`, `Group`, `Endpoint` and `Cluster`, and its conformance
//! column is the whole design:
//!
//! * `Node` is `Endpoint` — required when an endpoint is named.
//! * `Group` is `!Endpoint` — and an endpoint is `!Group`. A binding is *either* unicast
//!   (node + endpoint) *or* groupcast (group), never both.
//! * `Cluster` is optional, and narrows whichever of the two it is.
//!
//! A table that accepted both at once would describe a target with no meaning, and the node
//! would have to guess at send time — which is exactly the moment there is nobody to ask.
//! [`Target::is_valid`] refuses it at the door instead.

use core::cell::RefCell;
use core::marker::PhantomData;

use crate::config::Config;
use crate::dm::{
    Access, AccessQualities, AttributeDescriptor, AttributeQualities, ClusterDescriptor,
    CommandDescriptor, Privilege, Resolved,
};
use crate::im::{
    AttributeId, ClusterHandler, ClusterId, EndpointId, InteractionContext, Status, WriteOp,
};
use crate::msg::{FabricIndex, GroupId, NodeId};
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value};

use super::Cluster;

/// `0x001E` (§9.6.4).
pub const ID: ClusterId = 0x001E;

/// The revision §9.6.2's table ends on.
pub const REVISION: u16 = 1;

/// `Binding` (§9.6.6) — `list[TargetStruct]`, `RW VM F`, `N`, mandatory.
pub const BINDING: AttributeId = 0x0000;

/// The global `FabricIndex` field of a fabric-scoped struct (§7.19.1.9).
pub const FABRIC_INDEX_FIELD: u8 = 254;

/// One binding (§9.6.5.1's `TargetStruct`).
///
/// Either unicast — a `node` and an `endpoint` — or groupcast — a `group`. Never both, and
/// never neither. `cluster` narrows whichever it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Target {
    /// The fabric this binding belongs to, and the only one that can see it.
    pub fabric_index: FabricIndex,
    /// `Node [1]` — "the remote target node ID. If the Endpoint field is present, this field
    /// SHALL be present."
    pub node: Option<NodeId>,
    /// `Group [2]` — "the target group ID that represents remote endpoints".
    pub group: Option<GroupId>,
    /// `Endpoint [3]` — "the remote endpoint that the local endpoint is bound to".
    pub endpoint: Option<EndpointId>,
    /// `Cluster [4]` — optional, and narrows the target to one cluster on it.
    pub cluster: Option<ClusterId>,
}

impl Target {
    /// A unicast binding to one endpoint on one node.
    #[must_use]
    pub const fn unicast(fabric_index: FabricIndex, node: NodeId, endpoint: EndpointId) -> Self {
        Self {
            fabric_index,
            node: Some(node),
            group: None,
            endpoint: Some(endpoint),
            cluster: None,
        }
    }

    /// A groupcast binding to every endpoint in a group.
    #[must_use]
    pub const fn groupcast(fabric_index: FabricIndex, group: GroupId) -> Self {
        Self {
            fabric_index,
            node: None,
            group: Some(group),
            endpoint: None,
            cluster: None,
        }
    }

    /// The same binding, narrowed to one cluster on the target.
    #[must_use]
    pub const fn with_cluster(mut self, cluster: ClusterId) -> Self {
        self.cluster = Some(cluster);
        self
    }

    /// §9.6.5.1's conformance, as a predicate.
    ///
    /// * A group and an endpoint are mutually exclusive (`Group` is `!Endpoint`, and the
    ///   other way round): a binding is unicast or groupcast, not a contradiction.
    /// * An endpoint requires a node ("If the Endpoint field is present, this field SHALL be
    ///   present"), because an endpoint number alone names nothing.
    /// * Something must be named. An empty target is a relationship with nobody.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        if self.group.is_some() && self.endpoint.is_some() {
            return false;
        }
        if self.endpoint.is_some() && self.node.is_none() {
            return false;
        }
        // §7.21.2's tables bound a cluster id, and §7.19.2.27 bounds an endpoint number:
        // "Endpoint numbers SHALL NOT be 0xFFFF". A binding naming either outside its range
        // points at nothing that could exist, and is stored, read back and never resolved —
        // the same shape as an Access Control target, and the same answer.
        if let Some(cluster) = self.cluster
            && !crate::dm::mei::cluster_is_valid(cluster)
        {
            return false;
        }
        if let Some(endpoint) = self.endpoint
            && endpoint == 0xFFFF
        {
            return false;
        }
        // A node with no endpoint is still a target — §9.6.6.1's second example binds a
        // cluster on a node — so "names nothing" means neither a node nor a group.
        self.node.is_some() || self.group.is_some()
    }

    /// Whether this is a groupcast binding.
    #[must_use]
    pub const fn is_groupcast(&self) -> bool {
        self.group.is_some()
    }

    fn encode(&self, w: &mut TlvWriter<'_>) -> crate::error::Result<()> {
        w.start_structure(Tag::Anonymous)?;
        if let Some(node) = self.node {
            w.unsigned(Tag::Context(1), node.0)?;
        }
        if let Some(group) = self.group {
            w.unsigned(Tag::Context(2), u64::from(group.0))?;
        }
        if let Some(endpoint) = self.endpoint {
            w.unsigned(Tag::Context(3), u64::from(endpoint))?;
        }
        if let Some(cluster) = self.cluster {
            w.unsigned(Tag::Context(4), u64::from(cluster))?;
        }
        w.unsigned(
            Tag::Context(FABRIC_INDEX_FIELD),
            u64::from(self.fabric_index.0),
        )?;
        w.end_container()
    }
}

/// Reads one `TargetStruct` whose opening structure the caller has taken.
fn decode_target(reader: &mut TlvReader<'_>, fabric_index: FabricIndex) -> Result<Target, Status> {
    let mut target = Target {
        fabric_index,
        ..Target::default()
    };
    loop {
        let Some(element) = reader.next_element().map_err(|_| Status::InvalidAction)? else {
            return Err(Status::InvalidAction);
        };
        if element.value == Value::EndOfContainer {
            break;
        }
        let context = element.tag.context();
        // The `FabricIndex` a client sends is ignored: §7.19.1.9's field is set by the server
        // from the accessing fabric, so a client cannot write into another's table.
        if element.value.is_null() || context == Some(FABRIC_INDEX_FIELD) {
            reader
                .skip_value(&element)
                .map_err(|_| Status::InvalidAction)?;
            continue;
        }
        let value = element.unsigned().map_err(|_| Status::ConstraintError)?;
        match context {
            Some(1) => target.node = Some(NodeId(value)),
            Some(2) => {
                let id = u16::try_from(value).map_err(|_| Status::ConstraintError)?;
                // §9.6.5.1 constrains Group to "min 1"; group 0 is the null group.
                if id == 0 {
                    return Err(Status::ConstraintError);
                }
                target.group = Some(GroupId(id));
            }
            Some(3) => {
                target.endpoint = Some(u16::try_from(value).map_err(|_| Status::ConstraintError)?);
            }
            Some(4) => {
                target.cluster = Some(u32::try_from(value).map_err(|_| Status::ConstraintError)?);
            }
            _ => {}
        }
    }
    if !target.is_valid() {
        return Err(Status::ConstraintError);
    }
    Ok(target)
}

/// §9.6.6's one attribute: `RW VM F` and `N`.
const ATTRIBUTES: &[AttributeDescriptor] = &[AttributeDescriptor::read_write(BINDING)
    .with_access(
        Access::read_write_with(Privilege::View, Privilege::Manage)
            // The `F` of §9.6.6's `RW VM F`. Without it the interaction model's own
            // fabric check never fires, and the only thing scoping the list would be this
            // cluster remembering to do it — a second guard is not a first one.
            .with_qualities(AccessQualities::FABRIC_SCOPED),
    )
    .with_qualities(AttributeQualities::NON_VOLATILE)];

const NO_COMMANDS: &[CommandDescriptor] = &[];

/// The descriptor for this cluster.
#[must_use]
pub const fn cluster() -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id: ID,
        revision: REVISION,
        feature_map: 0,
        attributes: ATTRIBUTES,
        accepted_commands: NO_COMMANDS,
        generated_commands: &[],
        events: &[],
    }
}

/// The Binding cluster's table (§9.6.6.1).
///
/// `N` is the total across every fabric; §9.6.1 asks that a device type's minimum be available
/// "for each fabric the node supports", which is what [`Binding::per_fabric`] enforces.
#[derive(Debug)]
pub struct Binding<C: Config, const N: usize> {
    targets: RefCell<heapless::Vec<Target, N>>,
    per_fabric: usize,
    _config: PhantomData<C>,
}

impl<C: Config, const N: usize> Binding<C, N> {
    /// A table with no bindings — §9.6.6's fallback of `[]`.
    ///
    /// `per_fabric` is how many entries any one fabric may hold, so that the first fabric to
    /// fill the table cannot leave a later one unable to bind anything.
    #[must_use]
    pub const fn new(per_fabric: usize) -> Self {
        Self {
            targets: RefCell::new(heapless::Vec::new()),
            per_fabric,
            _config: PhantomData,
        }
    }

    /// The per-fabric quota.
    #[must_use]
    pub const fn per_fabric(&self) -> usize {
        self.per_fabric
    }

    /// Every binding, for a device about to persist them.
    #[must_use]
    pub fn targets(&self) -> core::cell::Ref<'_, heapless::Vec<Target, N>> {
        self.targets.borrow()
    }

    /// How many bindings one fabric holds.
    #[must_use]
    pub fn len_of_fabric(&self, fabric: FabricIndex) -> usize {
        self.targets
            .borrow()
            .iter()
            .filter(|t| t.fabric_index == fabric)
            .count()
    }

    /// Adds one binding.
    ///
    /// §9.6.1: "If, during the creation of multiple bindings, there are no available resources
    /// to create an entry … the client SHALL respond with a status of RESOURCE_EXHAUSTED, and
    /// the binding SHALL NOT be created."
    pub fn add(&self, target: Target) -> Result<(), Status> {
        if !target.is_valid() || target.fabric_index.0 == 0 {
            return Err(Status::ConstraintError);
        }
        if self.len_of_fabric(target.fabric_index) >= self.per_fabric {
            return Err(Status::ResourceExhausted);
        }
        self.targets
            .borrow_mut()
            .push(target)
            .map_err(|_| Status::ResourceExhausted)
    }

    /// Removes every binding of one fabric — what `RemoveFabric` must do.
    ///
    /// §9.6.1: "When a binding is removed, the client endpoint SHALL end the binding
    /// relationship with the removed binding target." Ending it is the application's; this is
    /// the table's half.
    pub fn remove_fabric(&self, fabric: FabricIndex) {
        self.targets
            .borrow_mut()
            .retain(|t| t.fabric_index != fabric);
    }

    /// Whether a fabric's entries belong in this read (§7.19.1.8.2).
    fn visible(ctx: &InteractionContext<'_>, index: FabricIndex) -> bool {
        !ctx.fabric_filtered || ctx.fabric_index == Some(index)
    }
}

impl<C: Config, const N: usize> ClusterHandler for Binding<C, N> {
    /// §9.6: the Binding table is fabric-scoped (`F`), so a removed fabric's targets go with
    /// it — otherwise this node keeps trying to reach a peer on a fabric it has left.
    fn on_lifecycle(&self, event: crate::im::Lifecycle) {
        if let crate::im::Lifecycle::FabricRemoved(fabric) = event {
            self.remove_fabric(fabric);
        }
    }
    fn read(
        &self,
        resolved: &Resolved<'_>,
        ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        if resolved.attribute != BINDING {
            return Err(Status::UnsupportedAttribute);
        }
        let full = |r: crate::error::Result<()>| r.map_err(|_| Status::ResourceExhausted);
        let targets = self.targets.borrow();
        full(w.start_array(tag))?;
        for target in targets
            .iter()
            .filter(|t| Self::visible(ctx, t.fabric_index))
        {
            full(target.encode(w))?;
        }
        full(w.end_container())
    }

    fn write(
        &self,
        resolved: &Resolved<'_>,
        data: &[u8],
        op: WriteOp,
        ctx: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        if resolved.attribute != BINDING {
            return Err(Status::UnsupportedWrite);
        }
        // §7.19.1.8.1: a fabric-scoped list needs an accessing fabric to scope the write to.
        let Some(fabric_index) = ctx.fabric_index else {
            return Err(Status::UnsupportedAccess);
        };

        let mut reader = TlvReader::new_in(data, ContainerKind::Structure);
        let element = reader
            .next_element()
            .map_err(|_| Status::InvalidAction)?
            .ok_or(Status::InvalidAction)?;

        match op {
            WriteOp::Replace => {
                if element.value.container() != Some(ContainerKind::Array) {
                    return Err(Status::InvalidAction);
                }
                let mut replacement: heapless::Vec<Target, N> = heapless::Vec::new();
                loop {
                    let Some(item) = reader.next_element().map_err(|_| Status::InvalidAction)?
                    else {
                        return Err(Status::InvalidAction);
                    };
                    if item.value == Value::EndOfContainer {
                        break;
                    }
                    if item.value.container() != Some(ContainerKind::Structure) {
                        return Err(Status::InvalidAction);
                    }
                    replacement
                        .push(decode_target(&mut reader, fabric_index)?)
                        .map_err(|_| Status::ResourceExhausted)?;
                }
                if replacement.len() > self.per_fabric {
                    return Err(Status::ResourceExhausted);
                }
                // Only this fabric's entries are replaced; the others were never visible to
                // the writer and are not its to remove. A replace that fails partway leaves
                // this fabric's list partly rebuilt, which §10.6.4.3.1 sanctions directly:
                // "clients that receive an error status for a write action to a list
                // attribute SHOULD NOT assume that the list contents are unchanged".
                let mut held = self.targets.borrow_mut();
                held.retain(|t| t.fabric_index != fabric_index);
                for target in replacement {
                    held.push(target).map_err(|_| Status::ResourceExhausted)?;
                }
            }
            WriteOp::Append => {
                if element.value.container() != Some(ContainerKind::Structure) {
                    return Err(Status::InvalidAction);
                }
                let target = decode_target(&mut reader, fabric_index)?;
                self.add(target)?;
            }
        }
        Ok(())
    }
}

impl<C: Config, const N: usize> Cluster for Binding<C, N> {
    const ID: ClusterId = ID;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DefaultConfig;

    type Table = Binding<DefaultConfig, 8>;

    const F1: FabricIndex = FabricIndex(1);
    const F2: FabricIndex = FabricIndex(2);
    const BULB: NodeId = NodeId(0x0000_0000_0006_F1F1);

    #[test]
    fn a_binding_is_unicast_or_groupcast_and_never_both() {
        // §9.6.5.1: `Group` is `!Endpoint` and `Endpoint` is `!Group`. A target that named
        // both would have no meaning, and the node would have to guess at send time.
        let both = Target {
            fabric_index: F1,
            node: Some(BULB),
            group: Some(GroupId(7)),
            endpoint: Some(1),
            cluster: None,
        };
        assert!(!both.is_valid());

        assert!(Target::unicast(F1, BULB, 1).is_valid());
        assert!(Target::groupcast(F1, GroupId(7)).is_valid());
    }

    #[test]
    fn an_endpoint_without_a_node_names_nothing() {
        // "If the Endpoint field is present, this field SHALL be present" — an endpoint
        // number on its own does not say whose.
        let orphan = Target {
            fabric_index: F1,
            node: None,
            group: None,
            endpoint: Some(1),
            cluster: None,
        };
        assert!(!orphan.is_valid());
    }

    #[test]
    fn an_empty_target_is_a_relationship_with_nobody() {
        assert!(!Target::default().is_valid());
    }

    #[test]
    fn a_target_naming_an_identifier_that_cannot_exist_is_refused() {
        // §7.21.2's MEI tables and §7.19.2.27's "Endpoint numbers SHALL NOT be 0xFFFF". A
        // binding pointing at a cluster or an endpoint outside its range resolves to nothing,
        // for ever, and nothing ever says so — the same shape as an Access Control target.
        assert!(
            !Target::groupcast(F1, GroupId(1))
                .with_cluster(0xFFFF_FFFF)
                .is_valid(),
            "prefix 0xFFFF is Invalid in Table 103's own words"
        );
        assert!(
            !Target::groupcast(F1, GroupId(1))
                .with_cluster(0x0000_8000)
                .is_valid(),
            "the gap between a standard cluster and a manufacturer-specific one"
        );
        assert!(
            !Target::unicast(F1, NodeId(456_789), 0xFFFF).is_valid(),
            "0xFFFF is not an endpoint number"
        );
        // And the shapes that are legal stay legal.
        assert!(
            Target::groupcast(F1, GroupId(1))
                .with_cluster(0xFFF1_FC00)
                .is_valid()
        );
        assert!(Target::unicast(F1, NodeId(456_789), 0xFFFE).is_valid());
    }

    #[test]
    fn a_cluster_narrows_either_kind() {
        // §9.6.6.1's two published examples: a switch bound to a group for On/Off, and a
        // sensor client bound to one cluster on one endpoint of one node.
        let switch = Target::groupcast(F1, GroupId(1234));
        assert!(switch.is_valid() && switch.is_groupcast());

        let sensor = Target::unicast(F1, NodeId(456_789), 3).with_cluster(1026);
        assert!(sensor.is_valid());
        assert_eq!(sensor.cluster, Some(1026));
        assert!(!sensor.is_groupcast());
    }

    #[test]
    fn the_binding_attribute_carries_every_quality_of_its_access_column() {
        // §9.6.6 gives `Binding` access `RW VM F` and quality `N`, and each letter does
        // something. Dropping the `F` is the quiet one: the interaction model's own
        // fabric-scoped check never fires, and the only thing scoping the list is the cluster
        // remembering to — which makes a second guard the first one.
        let descriptor = cluster();
        assert_eq!(descriptor.id, 0x001E);
        let attribute = descriptor.attribute(BINDING).expect("Binding");
        assert_eq!(attribute.access.read, Some(Privilege::View));
        assert_eq!(attribute.access.write, Some(Privilege::Manage));
        assert!(attribute.access.is_fabric_scoped(), "the `F`");
        assert!(
            attribute
                .qualities
                .contains(AttributeQualities::NON_VOLATILE),
            "the `N`"
        );
    }

    #[test]
    fn a_fabrics_quota_is_its_own() {
        // §9.6.1: a device type's minimum must be available "for each fabric the node
        // supports", so one fabric filling the table must not lock another out.
        let table = Table::new(2);
        table.add(Target::unicast(F1, BULB, 1)).expect("first");
        table.add(Target::unicast(F1, BULB, 2)).expect("second");
        assert_eq!(
            table.add(Target::unicast(F1, BULB, 3)).unwrap_err(),
            Status::ResourceExhausted
        );
        table
            .add(Target::unicast(F2, BULB, 1))
            .expect("another fabric has its own quota");
    }

    #[test]
    fn removing_a_fabric_takes_its_bindings() {
        let table = Table::new(4);
        table.add(Target::unicast(F1, BULB, 1)).expect("add");
        table.add(Target::unicast(F2, BULB, 1)).expect("add");
        table.remove_fabric(F1);
        assert_eq!(table.len_of_fabric(F1), 0);
        assert_eq!(table.len_of_fabric(F2), 1, "another fabric is untouched");
    }

    #[test]
    fn a_binding_on_no_fabric_is_refused() {
        // Fabric 0 names no fabric, so such a binding could never be read back or removed.
        let table = Table::new(4);
        assert_eq!(
            table
                .add(Target::unicast(FabricIndex(0), BULB, 1))
                .unwrap_err(),
            Status::ConstraintError
        );
    }
}
