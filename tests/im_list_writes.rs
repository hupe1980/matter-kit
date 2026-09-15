//! Writing a list attribute (Core §10.6.4.3.1, §8.7.3.3).
//!
//! A list may be larger than one message, so §10.6.4.3.1 lets a client send it as a series of
//! blocks: one that replaces the list, then one per item. The two kinds are told apart *only*
//! by the path — `ListIndex` omitted means REPLACE, `ListIndex` null means ADD — and never by
//! the data, which looks the same either way.
//!
//! That makes it a decision only the interaction-model layer can pass on, and getting it
//! wrong is silent. A server that hands a cluster the data without the operation leaves the
//! cluster to guess; a cluster that guesses "replace" keeps only the **last** item of every
//! list written this way, answers `SUCCESS` to all of it, and looks perfectly healthy. An
//! access control list is written exactly this way, so the failure is a device that quietly
//! drops every ACL entry but one.

#![cfg(feature = "std")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::cell::RefCell;
use matter_kit::dm::{AttributeDescriptor, ClusterDescriptor, Endpoint, Node, Privilege, Resolved};
use matter_kit::im::{
    AccessControl, AttributeData, AttributePath, InteractionContext, ListIndex, Outcome, Server,
    Status, WriteResponse,
};
use matter_kit::tlv::{ContainerKind, Tag, TlvWriter};

const ACL_ATTR: &[AttributeDescriptor] = &[AttributeDescriptor::read_write(0)];
const NO_CMDS: &[matter_kit::dm::CommandDescriptor] = &[];
const CL: &[ClusterDescriptor<'static>] = &[ClusterDescriptor {
    id: 0x001F,
    revision: 1,
    feature_map: 0,
    attributes: ACL_ATTR,
    accepted_commands: NO_CMDS,
    generated_commands: &[],
    events: &[],
}];
const ENDPOINTS: &[Endpoint<'static>] = &[Endpoint::new(0, CL)];

/// A cluster holding a list, written the way a controller writes an ACL.
#[derive(Default)]
struct ListCluster {
    items: RefCell<Vec<u64>>,
}

impl matter_kit::im::ClusterHandler for ListCluster {
    fn read(
        &self,
        _r: &Resolved<'_>,
        _c: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<(), Status> {
        w.unsigned(tag, 0).map_err(|_| Status::Failure)
    }

    fn write(
        &self,
        _r: &Resolved<'_>,
        data: &[u8],
        op: matter_kit::im::WriteOp,
        _c: &InteractionContext<'_>,
    ) -> Result<(), Status> {
        let mut r = matter_kit::tlv::TlvReader::new_in(data, ContainerKind::Structure);
        let first = r
            .next_element()
            .map_err(|_| Status::Failure)?
            .ok_or(Status::Failure)?;
        match op {
            matter_kit::im::WriteOp::Replace => {
                let mut new = Vec::new();
                if first.value.container() == Some(ContainerKind::Array) {
                    while let Some(e) = r.next_element().map_err(|_| Status::Failure)? {
                        if e.value == matter_kit::tlv::Value::EndOfContainer {
                            break;
                        }
                        new.push(e.unsigned().map_err(|_| Status::Failure)?);
                    }
                } else {
                    new.push(first.unsigned().map_err(|_| Status::Failure)?);
                }
                *self.items.borrow_mut() = new;
            }
            matter_kit::im::WriteOp::Append => {
                self.items
                    .borrow_mut()
                    .push(first.unsigned().map_err(|_| Status::Failure)?);
            }
        }
        Ok(())
    }
}

struct All;
impl AccessControl for All {
    fn allows(&self, _p: &AttributePath, _r: Privilege) -> Outcome {
        Outcome::Granted
    }
}

fn empty_array() -> Vec<u8> {
    let mut b = [0u8; 8];
    let mut w = TlvWriter::new_in(&mut b, ContainerKind::Structure);
    w.start_array(Tag::Context(2)).unwrap();
    w.end_container().unwrap();
    w.finish().unwrap().to_vec()
}
fn scalar(v: u64) -> Vec<u8> {
    let mut b = [0u8; 16];
    let mut w = TlvWriter::new_in(&mut b, ContainerKind::Structure);
    w.unsigned(Tag::Context(2), v).unwrap();
    w.finish().unwrap().to_vec()
}

/// Exactly §10.6.4.3.1's second pattern: clear the list, then append each item.
#[test]
fn a_controller_writing_a_list_item_by_item_keeps_every_item() {
    let cluster = ListCluster::default();
    let base = AttributePath::attribute(0, 0x001F, 0);
    let append = AttributePath {
        list_index: Some(ListIndex::Append),
        ..base
    };

    let clear = empty_array();
    let a = scalar(11);
    let b = scalar(22);
    let c = scalar(33);
    let writes = [
        AttributeData {
            data_version: None,
            path: base,
            data: &clear,
        },
        AttributeData {
            data_version: None,
            path: append,
            data: &a,
        },
        AttributeData {
            data_version: None,
            path: append,
            data: &b,
        },
        AttributeData {
            data_version: None,
            path: append,
            data: &c,
        },
    ];

    let mut buf = [0u8; 2048];
    let server = Server::new(Node::new(ENDPOINTS), &All, &cluster, 64);
    let (bytes, _) = server
        .serve_write(
            writes.iter().copied().map(Ok),
            &InteractionContext::default(),
            false,
            &mut buf,
        )
        .expect("serve_write");
    let response = WriteResponse::decode(bytes).expect("decode");
    for s in response.statuses().expect("statuses") {
        assert_eq!(s.expect("decode").status.status, Status::Success);
    }

    assert_eq!(
        *cluster.items.borrow(),
        vec![11, 22, 33],
        "all three appended items must survive"
    );
}

/// §10.6.4.3.1: "ListIndex is currently only allowed to be omitted or null. Any other value
/// SHALL be interpreted as an error."
///
/// Writing *at* an index is not something a client may ask for. Treating it as a replace —
/// which is what dropping the field silently does — would let a write meant for one item
/// destroy the whole list.
#[test]
fn a_write_at_a_list_index_is_refused_rather_than_treated_as_a_replace() {
    let cluster = ListCluster::default();
    *cluster.items.borrow_mut() = vec![1, 2, 3];

    let v = scalar(99);
    let at = AttributePath {
        list_index: Some(ListIndex::At(1)),
        ..AttributePath::attribute(0, 0x001F, 0)
    };
    let data = AttributeData {
        data_version: None,
        path: at,
        data: &v,
    };

    let mut buf = [0u8; 2048];
    let server = Server::new(Node::new(ENDPOINTS), &All, &cluster, 64);
    let (bytes, _) = server
        .serve_write(
            [data].iter().copied().map(Ok),
            &InteractionContext::default(),
            false,
            &mut buf,
        )
        .expect("serve_write");
    let response = WriteResponse::decode(bytes).expect("decode");
    let statuses: Vec<_> = response
        .statuses()
        .expect("statuses")
        .map(|s| s.expect("decode").status.status)
        .collect();
    assert_eq!(statuses, vec![Status::InvalidAction]);
    assert_eq!(
        *cluster.items.borrow(),
        vec![1, 2, 3],
        "the list is untouched"
    );
}

/// A replace with a non-empty array is §10.6.4.3.1's third pattern, and still a replace.
#[test]
fn a_replace_carrying_items_replaces_rather_than_appends() {
    let cluster = ListCluster::default();
    *cluster.items.borrow_mut() = vec![7, 8, 9];

    let mut b = [0u8; 32];
    let mut w = TlvWriter::new_in(&mut b, ContainerKind::Structure);
    w.start_array(Tag::Context(2)).unwrap();
    w.unsigned(Tag::Anonymous, 1).unwrap();
    w.unsigned(Tag::Anonymous, 2).unwrap();
    w.end_container().unwrap();
    let arr = w.finish().unwrap().to_vec();

    let base = AttributePath::attribute(0, 0x001F, 0);
    let data = AttributeData {
        data_version: None,
        path: base,
        data: &arr,
    };
    let mut buf = [0u8; 2048];
    let server = Server::new(Node::new(ENDPOINTS), &All, &cluster, 64);
    let _ = server
        .serve_write(
            [data].iter().copied().map(Ok),
            &InteractionContext::default(),
            false,
            &mut buf,
        )
        .expect("serve_write");
    assert_eq!(
        *cluster.items.borrow(),
        vec![1, 2],
        "replaced, not appended to"
    );
}
