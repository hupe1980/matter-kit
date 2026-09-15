//! The conformance engine against every cluster and every feature map (Core §7.3).
//!
//! Unlike the other targets this one is not defending against a stranger — the tables are
//! generated and the feature map comes from the device's own configuration. What it is
//! defending against is a *wrong answer*, which is worse here than a crash: a validator that
//! quietly demands the wrong elements, or a derived descriptor that advertises what the
//! specification forbids, produces a device that looks right and fails certification.
//!
//! Four properties, over all 135 clusters at arbitrary feature maps:
//!
//! 1. **Nothing panics, and the fixed point always settles.** An element's conformance may
//!    name another element, so the element set is computed by iteration; a library that
//!    oscillated would be a device that could not be built.
//! 2. **A derived descriptor validates against the table it came from.** The two halves of the
//!    engine — `Conforming` and `validate` — are written separately and must agree, or one of
//!    them is wrong about what the same expression means.
//! 3. **Deriving is deterministic.** The same inputs give the same descriptor, so a device
//!    that rebuilds one after a reboot advertises what it did before.
//! 4. **Nothing disallowed is ever selected.** The property the whole engine exists for: a
//!    feature map that forbids an element must not produce one that has it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use matter_kit::clusters::generated;
use matter_kit::dm::conformance::Conformance;
use matter_kit::dm::spec::{Conforming, Optional};

/// Big enough for the largest cluster in the 1.6 library.
type Built = Conforming<128, 64, 64, 32>;

fuzz_target!(|data: &[u8]| {
    // Two octets choose the cluster, four the feature map. Everything after is the set of
    // optional elements the "product" claims, which is what conformance cannot derive.
    let Some(head) = data.get(..6) else {
        return;
    };
    let index = usize::from(u16::from_le_bytes([head[0], head[1]]));
    let Some(cluster) = generated::ALL
        .get(index % generated::ALL.len().max(1))
        .copied()
    else {
        return;
    };
    let feature_map = u32::from_le_bytes([head[2], head[3], head[4], head[5]]);

    // An id the cluster does not define is simply never matched, so arbitrary bytes are a
    // legitimate — and interesting — optional set.
    let rest = data.get(6..).unwrap_or_default();
    let attributes: Vec<u32> = rest
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    let commands: Vec<u32> = attributes.iter().map(|a| a & 0xFF).collect();
    let events: Vec<u32> = attributes.iter().map(|a| (a >> 8) & 0xFF).collect();
    let optional = Optional {
        attributes: &attributes,
        commands: &commands,
        events: &events,
    };

    // Property 1. A feature bit the cluster does not define is refused rather than ignored,
    // so most random maps land here — which is the correct answer, not a missed case.
    let Ok(built) = Built::new(cluster, feature_map, &optional) else {
        return;
    };
    let descriptor = built.descriptor();

    // Property 4, checked directly against the tables rather than through the validator, so
    // the two halves cannot agree on the same mistake.
    for attribute in cluster.attributes {
        if attribute.conform.verdict(&Probe {
            descriptor: &descriptor,
        }) == Conformance::Disallowed
        {
            assert!(
                !descriptor.attributes.iter().any(|a| a.id == attribute.id),
                "{} served a disallowed attribute {:#06X}",
                cluster.name,
                attribute.id
            );
        }
    }

    // Property 2.
    let mut defects = Vec::new();
    cluster.validate(&descriptor, |defect| defects.push(defect));
    assert!(
        defects.is_empty(),
        "{} at {feature_map:#010x}: a derived descriptor is not conformant: {defects:?}",
        cluster.name
    );

    // Property 3.
    let again = Built::new(cluster, feature_map, &optional).expect("the same inputs");
    let second = again.descriptor();
    assert_eq!(descriptor.attributes.len(), second.attributes.len());
    assert_eq!(
        descriptor.accepted_commands.len(),
        second.accepted_commands.len()
    );
    assert_eq!(descriptor.events.len(), second.events.len());

    // The descriptor must also be well formed — sorted, no duplicates — because every lookup
    // in the interaction model binary-searches it.
    assert!(
        descriptor.is_well_formed(),
        "{} produced an unsorted descriptor",
        cluster.name
    );
});

/// What the derived descriptor supports, for evaluating a condition against it.
struct Probe<'a> {
    descriptor: &'a matter_kit::dm::ClusterDescriptor<'a>,
}

impl matter_kit::dm::conformance::Supports for Probe<'_> {
    fn feature_map(&self) -> u32 {
        self.descriptor.feature_map
    }
    fn has_attribute(&self, id: u32) -> bool {
        self.descriptor.attributes.iter().any(|a| a.id == id)
    }
    fn has_command(&self, id: u32) -> bool {
        self.descriptor.generated_command_ids().any(|c| c == id)
            || self.descriptor.accepted_commands.iter().any(|c| c.id == id)
    }
    fn has_event(&self, id: u32) -> bool {
        self.descriptor.events.iter().any(|e| e.id == id)
    }
    fn has_cluster(&self, _id: u32) -> bool {
        false
    }
}
