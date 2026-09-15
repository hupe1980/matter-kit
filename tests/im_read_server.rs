//! Serving a Read, against Core §8.4.3.2's fifteen numbered steps.
//!
//! The rules there are precise and the interesting ones are about *what a client is told*
//! rather than what it gets. Two in particular decide the shape of a conforming server, and
//! both are easy to get wrong in a way that works:
//!
//! 1. **A concrete path gets a status; an expanded path is discarded.** §8.4.3.2 step 1b
//!    generates an `AttributeStatusIB` for a concrete path that fails a check; step 1c says
//!    an expanded one "SHALL be discarded". A server that reported statuses for wildcard
//!    expansions would work perfectly and leak the shape of a node to a subject with no
//!    privilege over it — every denied cluster would announce itself.
//!
//! 2. **A concrete path is access-checked twice, and the first one comes first.** Step b.i
//!    checks at View "to determine whether the subject would have had at least some access"
//!    *before* the existence checks of step b.ii. Reversing them is the natural way to write
//!    it and tells an unprivileged subject `UNSUPPORTED_CLUSTER` — which is a map of the node.
//!
//! Neither is visible in a test that only reads attributes it is allowed to read.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use matter_kit::dm::{
    Access, AttributeDescriptor, ClusterDescriptor, CommandDescriptor, Endpoint, Node, Privilege,
    Resolved, global,
};
use matter_kit::im::{
    AccessControl, AttributePath, AttributeReport, Outcome, ReportData, Server, Status,
};
use matter_kit::tlv::{Tag, TlvWriter};

const ON_OFF: u32 = 0x0006;
const LEVEL: u32 = 0x0008;
const BASIC: u32 = 0x0028;

/// `OnOff` is readable at View; `StartUpOnOff` needs Manage to write; `Secret` is
/// write-only, which a read must answer `UNSUPPORTED_READ` for.
const ON_OFF_ATTRS: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_only(0x0000),
    AttributeDescriptor::read_write(0x4003)
        .with_access(Access::read_write_with(Privilege::View, Privilege::Manage)),
    AttributeDescriptor::read_only(0x4100).with_access(Access::write_only(Privilege::Manage)),
];
const LEVEL_ATTRS: &[AttributeDescriptor] = &[AttributeDescriptor::read_only(0x0000)];
/// A cluster whose only attribute needs Administer to read.
const BASIC_ATTRS: &[AttributeDescriptor] = &[
    AttributeDescriptor::read_only(0x0001).with_access(Access::read_only(Privilege::Administer))
];
const NO_CMDS: &[CommandDescriptor] = &[];

const fn cluster(
    id: u32,
    attributes: &'static [AttributeDescriptor],
) -> ClusterDescriptor<'static> {
    ClusterDescriptor {
        id,
        revision: 3,
        feature_map: 0,
        attributes,
        accepted_commands: NO_CMDS,
        generated_commands: &[],
        events: &[],
    }
}

const EP0: &[ClusterDescriptor<'static>] = &[cluster(BASIC, BASIC_ATTRS)];
const EP1: &[ClusterDescriptor<'static>] =
    &[cluster(ON_OFF, ON_OFF_ATTRS), cluster(LEVEL, LEVEL_ATTRS)];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(0, EP0), Endpoint::new(1, EP1)];

fn node() -> Node<'static> {
    Node::new(ENDPOINTS)
}

/// A reader that answers every attribute with `42` and tracks a data version.
struct Fake;

impl matter_kit::im::ClusterHandler for Fake {
    fn read(
        &self,
        _resolved: &Resolved<'_>,
        _ctx: &matter_kit::im::InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        w.unsigned(tag, 42).map_err(|_| Status::Failure)
    }

    fn data_version(&self, _resolved: &Resolved<'_>) -> Option<u32> {
        Some(7)
    }
}

/// An access control holding one privilege over everything.
struct Holds(Privilege);

impl AccessControl for Holds {
    fn allows(&self, _path: &AttributePath, required: Privilege) -> Outcome {
        if self.0.grants(required) {
            Outcome::Granted
        } else {
            Outcome::Denied
        }
    }
}

/// An access control that denies one cluster outright and grants the rest.
struct DeniesCluster(u32);

impl AccessControl for DeniesCluster {
    fn allows(&self, path: &AttributePath, _required: Privilege) -> Outcome {
        if path.cluster == Some(self.0) {
            Outcome::Denied
        } else {
            Outcome::Granted
        }
    }
}

/// An access control that restricts everything — §6.6.3's Access Restriction List.
struct Restricts;

impl AccessControl for Restricts {
    fn allows(&self, _path: &AttributePath, _required: Privilege) -> Outcome {
        Outcome::Restricted
    }
}

fn read<A: AccessControl>(
    paths: &[AttributePath],
    access: &A,
    limit: usize,
) -> (heapless::Vec<u8, 2048>, matter_kit::im::ReadOutcome) {
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let server = Server::new(node(), access, &Fake, limit);
    let (bytes, outcome) = server
        .serve(
            paths.iter().copied().map(Ok),
            &matter_kit::im::InteractionContext::default(),
            None,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    (heapless::Vec::from_slice(bytes).expect("fits"), outcome)
}

/// Decodes a report into (path, status-or-data) pairs.
fn decode(bytes: &[u8]) -> Vec<(AttributePath, Option<Status>)> {
    let report = ReportData::decode(bytes).expect("decode");
    let Some(iter) = report.attribute_reports().expect("reports") else {
        return Vec::new();
    };
    iter.map(|item| {
        let item = item.expect("decode each");
        match item {
            AttributeReport::Status(s) => (s.path, Some(s.status.status)),
            AttributeReport::Data(d) => (d.path, None),
        }
    })
    .collect()
}

// --- The asymmetry that matters ---------------------------------------------------------------

#[test]
fn a_concrete_path_that_is_denied_is_told_so() {
    // §8.4.3.2 step b.i.A: "an AttributeStatusIB SHALL be generated with the
    // UNSUPPORTED_ACCESS Status Code."
    let path = AttributePath::attribute(1, ON_OFF, 0x0000);
    let (bytes, outcome) = read(&[path], &DeniesCluster(ON_OFF), 64);
    assert_eq!(outcome.reports, 1);
    assert_eq!(
        decode(&bytes),
        vec![(path, Some(Status::UnsupportedAccess))]
    );
}

#[test]
fn a_wildcard_expansion_that_is_denied_is_silently_discarded() {
    // §8.4.3.2 step c.ii.A: "then the path SHALL be discarded." No status — and that is the
    // privacy property. A server that reported statuses here would work, and would let a
    // subject with no privilege over On/Off learn that On/Off is there by counting them.
    let (bytes, outcome) = read(&[AttributePath::wildcard()], &DeniesCluster(ON_OFF), 64);
    let reports = decode(&bytes);
    assert_eq!(outcome.reports, reports.len());
    assert!(
        reports.iter().all(|(path, _)| path.cluster != Some(ON_OFF)),
        "the denied cluster must not appear at all"
    );
    assert!(
        reports.iter().all(|(_, status)| status.is_none()),
        "a wildcard read produces data or nothing, never a status"
    );
    // And the clusters it *is* allowed still come through.
    assert!(reports.iter().any(|(path, _)| path.cluster == Some(LEVEL)));
}

#[test]
fn the_view_check_runs_before_the_existence_checks() {
    // §8.4.3.2 orders step b.i (access at View) before step b.ii (existence). Reversing them
    // is the natural way to write it, and tells an unprivileged subject the difference
    // between a cluster that is missing and one it may not have — which is a map of the node.
    //
    // Here the path names a cluster that does *not* exist on this endpoint, and the subject
    // is denied everything. A conforming server says UNSUPPORTED_ACCESS, not
    // UNSUPPORTED_CLUSTER.
    let path = AttributePath::attribute(1, 0xDEAD, 0x0000);
    let (bytes, _) = read(&[path], &DeniesCluster(0xDEAD), 64);
    assert_eq!(
        decode(&bytes),
        vec![(path, Some(Status::UnsupportedAccess))],
        "existence must not leak past a failed access check"
    );
}

#[test]
fn a_restricted_path_is_distinguished_from_a_denied_one() {
    // §8.4.3.2 step b.i.B: ACCESS_RESTRICTED, which §6.6.3's Access Restriction List
    // produces. It is a different answer because it means something different: the subject
    // has the privilege, and a restriction bars this particular use.
    let path = AttributePath::attribute(1, ON_OFF, 0x0000);
    let (bytes, _) = read(&[path], &Restricts, 64);
    assert_eq!(decode(&bytes), vec![(path, Some(Status::AccessRestricted))]);
}

// --- Existence, level by level -----------------------------------------------------------------

#[test]
fn each_missing_level_gets_its_own_status() {
    // §8.4.3.2 step b.ii.B through D. A client uses the difference to tell a missing endpoint
    // from a missing feature on an endpoint that is there.
    let cases = [
        (
            AttributePath::attribute(9, ON_OFF, 0),
            Status::UnsupportedEndpoint,
        ),
        (
            AttributePath::attribute(1, 0xDEAD, 0),
            Status::UnsupportedCluster,
        ),
        (
            AttributePath::attribute(1, ON_OFF, 0xDEAD),
            Status::UnsupportedAttribute,
        ),
    ];
    for (path, expected) in cases {
        let (bytes, _) = read(&[path], &Holds(Privilege::Administer), 64);
        assert_eq!(decode(&bytes), vec![(path, Some(expected))], "{path:?}");
    }
}

#[test]
fn a_write_only_attribute_read_is_unsupported_read_not_unsupported_attribute() {
    // §8.4.3.2 step b.ii.E. The attribute exists; it just cannot be read. Answering
    // UNSUPPORTED_ATTRIBUTE would tell a client to stop asking for something that is there.
    let path = AttributePath::attribute(1, ON_OFF, 0x4100);
    let (bytes, _) = read(&[path], &Holds(Privilege::Administer), 64);
    assert_eq!(decode(&bytes), vec![(path, Some(Status::UnsupportedRead))]);
}

#[test]
fn an_unreadable_attribute_is_discarded_from_a_wildcard() {
    // §8.4.3.2 step c.i: "If the path indicates attribute data that is not readable, then
    // the path SHALL be discarded." Not a status, even though a concrete read of the same
    // attribute gets one.
    let (bytes, _) = read(
        &[AttributePath::cluster(1, ON_OFF)],
        &Holds(Privilege::Administer),
        64,
    );
    let reports = decode(&bytes);
    assert!(
        reports
            .iter()
            .all(|(path, _)| path.attribute != Some(0x4100)),
        "the write-only attribute is not in a wildcard expansion's output"
    );
    assert!(
        reports
            .iter()
            .any(|(path, _)| path.attribute == Some(0x0000))
    );
}

// --- Privilege ---------------------------------------------------------------------------------

#[test]
fn a_view_subject_cannot_read_an_administer_attribute() {
    let path = AttributePath::attribute(0, BASIC, 0x0001);
    let (bytes, _) = read(&[path], &Holds(Privilege::View), 64);
    assert_eq!(
        decode(&bytes),
        vec![(path, Some(Status::UnsupportedAccess))]
    );

    // And an administrator can.
    let (bytes, _) = read(&[path], &Holds(Privilege::Administer), 64);
    assert_eq!(decode(&bytes), vec![(path, None)], "data, not a status");
}

#[test]
fn a_view_subject_reading_everything_sees_only_what_it_may() {
    // The two rules together: a whole-node wildcard from a View subject silently omits the
    // Administer-only attribute, and returns everything else.
    let (bytes, _) = read(&[AttributePath::wildcard()], &Holds(Privilege::View), 64);
    let reports = decode(&bytes);
    assert!(
        reports
            .iter()
            .all(|(path, _)| !(path.cluster == Some(BASIC) && path.attribute == Some(0x0001))),
        "the Administer attribute is omitted"
    );
    // But Basic's *global* attributes are readable at View, so the cluster still appears.
    assert!(
        reports.iter().any(|(path, _)| path.cluster == Some(BASIC)
            && path.attribute == Some(global::CLUSTER_REVISION)),
        "a denied attribute does not hide its cluster's globals"
    );
}

// --- Content ------------------------------------------------------------------------------------

#[test]
fn a_wildcard_read_returns_data_for_every_readable_path() {
    let (bytes, outcome) = read(
        &[AttributePath::wildcard()],
        &Holds(Privilege::Administer),
        64,
    );
    let reports = decode(&bytes);
    // Basic 1 + OnOff 2 readable (0x0000, 0x4003) + Level 1, plus five globals per cluster.
    assert_eq!(reports.len(), 1 + 2 + 1 + 3 * 5);
    assert_eq!(outcome.reports, reports.len());
    assert!(!outcome.truncated);
    assert!(reports.iter().all(|(_, status)| status.is_none()));
    assert!(
        reports.iter().all(|(path, _)| !path.has_wildcard()),
        "§8.4.3.2: 'Each path indicated by the Report Data action SHALL be a Concrete Path'"
    );
}

#[test]
fn the_global_attributes_are_served_by_the_model_not_the_cluster() {
    // A cluster never implements ClusterRevision; the model synthesises it from the
    // descriptor. The fake reader answers 42 to everything, so a revision of 3 proves it was
    // never consulted.
    let path = AttributePath::attribute(1, ON_OFF, global::CLUSTER_REVISION);
    let (bytes, _) = read(&[path], &Holds(Privilege::View), 64);
    let report = ReportData::decode(&bytes).expect("decode");
    let first = report
        .attribute_reports()
        .expect("reports")
        .expect("present")
        .next()
        .expect("one")
        .expect("decode");
    match first {
        AttributeReport::Data(data) => {
            // Context tag 2, one-octet unsigned, value 3 — the descriptor's revision.
            assert_eq!(data.data, &[0x24, 0x02, 3]);
            assert_eq!(data.data_version, Some(7));
        }
        AttributeReport::Status(s) => panic!("expected data, got {:?}", s.status.status),
    }
}

#[test]
fn a_data_version_is_carried_when_the_cluster_tracks_one() {
    let (bytes, _) = read(
        &[AttributePath::attribute(1, LEVEL, 0x0000)],
        &Holds(Privilege::View),
        64,
    );
    let report = ReportData::decode(&bytes).expect("decode");
    let first = report
        .attribute_reports()
        .expect("reports")
        .expect("present")
        .next()
        .expect("one")
        .expect("decode");
    match first {
        AttributeReport::Data(data) => assert_eq!(data.data_version, Some(7)),
        AttributeReport::Status(_) => panic!("expected data"),
    }
}

// --- Limits ---------------------------------------------------------------------------------

#[test]
fn a_one_message_read_refuses_rather_than_promising_more() {
    // §10.2.3's `MoreChunkedMessages` is a *promise*: the message that sets it says another
    // follows, and a client that is told this waits. `serve` has nowhere to resume from, so
    // it cannot honour that promise — and therefore must not make it. Refusing is the only
    // honest answer, and it names the method that can serve the read.
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = Holds(Privilege::Administer);
    let server = Server::new(node(), &access, &Fake, 3);
    let err = server
        .serve(
            [AttributePath::wildcard()].iter().copied().map(Ok),
            &matter_kit::im::InteractionContext::default(),
            None,
            &mut scratch,
            &mut buf,
        )
        .expect_err("a wildcard past the limit does not fit one message");
    assert_eq!(err.code(), matter_kit::ErrorCode::ReportWouldChunk);
}

#[test]
fn a_complete_read_does_not_claim_more_is_coming() {
    let (bytes, outcome) = read(
        &[AttributePath::attribute(1, LEVEL, 0x0000)],
        &Holds(Privilege::View),
        64,
    );
    assert!(!outcome.truncated);
    assert!(
        !ReportData::decode(&bytes)
            .expect("decode")
            .more_chunked_messages
    );
}

#[test]
fn an_empty_result_is_a_valid_report() {
    // §8.4.3.2 step 2: "If no error-free existent paths remain, then AttributeRequests are
    // considered empty." A wildcard naming a missing endpoint is not an error.
    let path = AttributePath {
        endpoint: Some(9),
        ..AttributePath::wildcard()
    };
    let (bytes, outcome) = read(&[path], &Holds(Privilege::Administer), 64);
    assert_eq!(outcome.reports, 0);
    assert!(!outcome.truncated);
    let report = ReportData::decode(&bytes).expect("a well-formed, empty report");
    assert_eq!(
        report
            .attribute_reports()
            .expect("reports")
            .map_or(0, |iter| iter.count()),
        0
    );
}

#[test]
fn tag_compression_is_refused_rather_than_misread() {
    // §10.6.2.1's scheme is provisional, and an unresolved inherited field would read as a
    // wildcard — turning a narrow request into a whole-node read. INVALID_ACTION is the
    // honest answer.
    let path = AttributePath {
        enable_tag_compression: true,
        ..AttributePath::attribute(1, ON_OFF, 0x0000)
    };
    let (bytes, _) = read(&[path], &Holds(Privilege::Administer), 64);
    assert_eq!(decode(&bytes), vec![(path, Some(Status::InvalidAction))]);
}

#[test]
fn a_tag_compressed_wildcard_is_discarded_rather_than_echoed() {
    // The refusal above may only name a path it can name. §8.2.1: "Each path indicated by the
    // Report Data action SHALL be a Concrete Path" — and a tag-compressed path with fields
    // missing is not one, because §10.6.2.1 says the inherited values "MAY still be missing.
    // In that case … they indicate wildcard semantics". Echoing the client's path verbatim
    // puts a wildcard in a report, which no client can attribute to an attribute.
    //
    // So it is discarded, exactly as §8.4.3.2 step 1c discards any expanded path that cannot
    // be served.
    let path = AttributePath {
        enable_tag_compression: true,
        ..AttributePath::wildcard()
    };
    let (bytes, outcome) = read(&[path], &Holds(Privilege::Administer), 64);
    assert_eq!(outcome.reports, 0, "nothing is reported for it");
    for (reported, _) in decode(&bytes) {
        assert!(
            !reported.has_wildcard(),
            "a reported path is always concrete"
        );
    }
}

#[test]
fn several_paths_are_served_in_order() {
    let paths = [
        AttributePath::attribute(1, ON_OFF, 0x0000),
        AttributePath::attribute(9, ON_OFF, 0x0000),
        AttributePath::attribute(1, LEVEL, 0x0000),
    ];
    let (bytes, outcome) = read(&paths, &Holds(Privilege::Administer), 64);
    assert_eq!(outcome.reports, 3);
    let reports = decode(&bytes);
    assert_eq!(reports[0], (paths[0], None));
    assert_eq!(reports[1], (paths[1], Some(Status::UnsupportedEndpoint)));
    assert_eq!(reports[2], (paths[2], None));
}

// --- §8.4.3.2 step 3.a: DataVersionFilters ---------------------------------------------------

/// Encodes a `DataVersionFilters` array the way a `ReadRequest` carries it: the array element
/// itself, tag and all, because that is the slice the request hands over.
fn filters(entries: &[(Option<u16>, Option<u32>, u32)]) -> heapless::Vec<u8, 256> {
    use matter_kit::im::{ClusterPath, DataVersionFilter};
    use matter_kit::tlv::{Tag, TlvWriter};

    let mut buf = [0u8; 256];
    let mut w = TlvWriter::new_in(&mut buf, matter_kit::tlv::ContainerKind::Structure);
    w.start_array(Tag::Context(3)).expect("array");
    for (endpoint, cluster, version) in entries {
        DataVersionFilter {
            path: ClusterPath {
                node: None,
                endpoint: *endpoint,
                cluster: *cluster,
            },
            data_version: *version,
        }
        .encode(&mut w)
        .expect("entry");
    }
    w.end_container().expect("end");
    heapless::Vec::from_slice(w.finish().expect("finish")).expect("fits")
}

fn read_filtered(paths: &[AttributePath], encoded: &[u8]) -> Vec<(AttributePath, Option<Status>)> {
    let mut scratch = [0u8; 512];
    let mut buf = [0u8; 2048];
    let access = Holds(Privilege::Administer);
    let server = Server::new(node(), &access, &Fake, 64);
    let ctx = matter_kit::im::InteractionContext::default().with_data_version_filters(encoded);
    let (bytes, _) = server
        .serve(
            paths.iter().copied().map(Ok),
            &ctx,
            None,
            &mut scratch,
            &mut buf,
        )
        .expect("serve");
    decode(bytes)
}

#[test]
fn a_matching_data_version_filter_omits_the_path_entirely() {
    // §8.4.3.2 step 3.a: "the path SHALL be ignored". Ignored, not refused — no AttributeDataIB
    // and no AttributeStatusIB either. The requester already holds the value; a status would be
    // this node telling it something went wrong when nothing did.
    let path = AttributePath::attribute(1, LEVEL, 0x0000);
    let reported = read_filtered(&[path], &filters(&[(Some(1), Some(LEVEL), 7)]));
    assert!(
        reported.is_empty(),
        "a cluster the requester already holds was reported anyway: {reported:?}"
    );
}

#[test]
fn a_stale_data_version_filter_sends_the_data() {
    // The filter says version 6; the cluster is at 7. The requester's copy is out of date, which
    // is the whole reason it sent a version rather than nothing.
    let path = AttributePath::attribute(1, LEVEL, 0x0000);
    let reported = read_filtered(&[path], &filters(&[(Some(1), Some(LEVEL), 6)]));
    assert_eq!(reported.len(), 1, "a stale filter suppressed live data");
    assert_eq!(reported[0].1, None, "expected data, got a status");
}

#[test]
fn a_filter_for_another_cluster_does_not_suppress_this_one() {
    let path = AttributePath::attribute(1, LEVEL, 0x0000);
    let reported = read_filtered(&[path], &filters(&[(Some(1), Some(ON_OFF), 7)]));
    assert_eq!(
        reported.len(),
        1,
        "a filter matched a cluster it does not name"
    );
}

#[test]
fn contradictory_filters_for_one_cluster_send_the_data() {
    // The quantifier in step 3.a is the rule: "**all** matching entries have a DataVersion field
    // that matches". Two entries for the same cluster with different versions cannot both be
    // what the requester holds, so it is told nothing and sent the data.
    //
    // Written with `any` instead of `all`, this test is the one that fails: the first entry
    // matches, the path is dropped, and the requester keeps a version it does not have.
    let path = AttributePath::attribute(1, LEVEL, 0x0000);
    let reported = read_filtered(
        &[path],
        &filters(&[(Some(1), Some(LEVEL), 7), (Some(1), Some(LEVEL), 6)]),
    );
    assert_eq!(
        reported.len(),
        1,
        "contradictory filters were treated as agreement"
    );
}

#[test]
fn a_wildcard_filter_path_matches_every_cluster_it_leaves_open() {
    // §10.6.2's `ClusterPathIB` leaves both fields optional, so a filter naming only an endpoint
    // covers every cluster on it — which is how a client says "nothing on endpoint 1 has moved".
    let reported = read_filtered(
        &[AttributePath {
            endpoint: Some(1),
            ..AttributePath::wildcard()
        }],
        &filters(&[(Some(1), None, 7)]),
    );
    assert!(
        reported.is_empty(),
        "an endpoint-wide filter left something behind: {reported:?}"
    );
    // …and it stops at that endpoint.
    let elsewhere = read_filtered(
        &[AttributePath {
            endpoint: Some(0),
            ..AttributePath::wildcard()
        }],
        &filters(&[(Some(1), None, 7)]),
    );
    assert!(
        !elsewhere.is_empty(),
        "a filter for endpoint 1 suppressed endpoint 0"
    );
}

#[test]
fn no_filters_reports_everything() {
    let path = AttributePath::attribute(1, LEVEL, 0x0000);
    let reported = read_filtered(&[path], &filters(&[]));
    assert_eq!(reported.len(), 1, "an empty filter list suppressed a path");
}

// --- §8.9.2.6: which wildcard combinations a Read may use ------------------------------------

#[test]
fn a_wildcard_cluster_with_a_concrete_non_global_attribute_is_invalid() {
    // §8.9.2.6's table admits "Endpoint specific, Cluster wildcard, Attribute specific" only for
    // a *global* attribute — the row says "a specific **global** attribute data or field for all
    // clusters". There is no row for a non-global one.
    //
    // Attribute ids are unique only within a cluster: `0x0000` names something different on
    // every one of them, so "attribute 0x0000 on every cluster" asks for a set of unrelated
    // values that share a number. Globals are exempt because their ids mean the same thing
    // everywhere.
    let path = AttributePath {
        endpoint: Some(1),
        cluster: None,
        attribute: Some(0x0000),
        ..AttributePath::wildcard()
    };
    assert!(
        !path.is_valid_for_read(),
        "a wildcard cluster with a concrete non-global attribute was admitted"
    );

    // The same shape with a global attribute is the row that *is* in the table.
    let global = AttributePath {
        attribute: Some(matter_kit::dm::global::CLUSTER_REVISION),
        ..path
    };
    assert!(
        global.is_valid_for_read(),
        "a wildcard cluster with a global attribute is what the table's row is for"
    );

    // And every fully-wildcard or fully-concrete shape stays legal.
    assert!(AttributePath::wildcard().is_valid_for_read());
    assert!(AttributePath::attribute(1, ON_OFF, 0x0000).is_valid_for_read());
    assert!(
        AttributePath {
            endpoint: None,
            cluster: Some(ON_OFF),
            attribute: Some(0x0000),
            ..AttributePath::wildcard()
        }
        .is_valid_for_read(),
        "a concrete cluster with a concrete attribute across endpoints is legal"
    );
}
