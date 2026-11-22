//! The DNS-SD set a node publishes, for each of the states that decide it (§4.3.1, §4.3.2,
//! §11.19.7).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use heapless::String;
use matter_kit::discovery::advertiser::{Advertiser, Identity, OpenWindow};
use matter_kit::discovery::{
    COMMISSIONABLE_SERVICE, CommissioningMode, OPERATIONAL_SERVICE, Responder,
};
use matter_kit::msg::VendorId;
use matter_kit::platform::sim::SimRng;

const IDENTITY: Identity = Identity {
    discriminator: 3840,
    vendor_id: VendorId(0xFFF1),
    product_id: 0x8000,
    port: 5540,
};

fn advertiser(seed: u64) -> Advertiser<5, 6> {
    Advertiser::new(IDENTITY, &SimRng::new(seed)).expect("advertiser")
}

fn fabric(i: u8) -> (String<33>, String<18>) {
    let mut name = String::new();
    let _ = core::fmt::Write::write_fmt(&mut name, format_args!("{i:016X}-{i:016X}"));
    let mut subtype = String::new();
    let _ = core::fmt::Write::write_fmt(&mut subtype, format_args!("_I{i:016X}"));
    (name, subtype)
}

fn txt_has(txt: &[u8], key_value: &str) -> bool {
    let mut rest = txt;
    while let Some((&len, tail)) = rest.split_first() {
        let (entry, next) = tail.split_at(usize::from(len).min(tail.len()));
        if entry == key_value.as_bytes() {
            return true;
        }
        rest = next;
    }
    false
}

#[test]
fn a_fresh_node_is_commissionable_with_its_factory_discriminator() {
    let a = advertiser(1);
    let set = a.advertisements();
    assert_eq!(set.len(), 1);
    assert_eq!(set[0].service, COMMISSIONABLE_SERVICE);
    assert!(set[0].subtypes.contains(&"_L3840"));
    assert!(set[0].subtypes.contains(&"_S15"));
    assert!(set[0].subtypes.contains(&"_CM"));
    assert!(txt_has(set[0].txt, "D=3840"));
    assert!(txt_has(set[0].txt, "CM=1"));
}

#[test]
fn three_fabrics_publish_three_operational_records_and_nothing_commissionable() {
    let mut a = advertiser(1);
    a.refresh([fabric(1), fabric(2), fabric(3)], None).unwrap();
    let set = a.advertisements();
    assert_eq!(set.len(), 3, "one per fabric, not only the first");
    for (i, ad) in set.iter().enumerate() {
        assert_eq!(ad.service, OPERATIONAL_SERVICE);
        assert_eq!(ad.instance, fabric(u8::try_from(i + 1).unwrap()).0.as_str());
    }
    assert!(!a.is_commissionable(), "commissioned and no window open");
}

#[test]
fn a_commissioned_node_with_an_enhanced_window_advertises_both() {
    let mut a = advertiser(1);
    let window = OpenWindow {
        discriminator: 1234,
        mode: CommissioningMode::Enhanced,
    };
    a.refresh([fabric(1)], Some(window)).unwrap();
    let set = a.advertisements();
    assert_eq!(set.len(), 2);
    assert_eq!(
        set[0].service, OPERATIONAL_SERVICE,
        "the fabric keeps reaching it"
    );
    let commissionable = &set[1];
    assert_eq!(commissionable.service, COMMISSIONABLE_SERVICE);
    assert!(
        commissionable.subtypes.contains(&"_L1234"),
        "the window's discriminator, not the factory one"
    );
    assert!(txt_has(commissionable.txt, "CM=2"));
}

#[test]
fn the_window_closing_withdraws_the_commissionable_record() {
    let mut a = advertiser(1);
    let window = OpenWindow {
        discriminator: 1234,
        mode: CommissioningMode::Basic,
    };
    a.refresh([fabric(1)], Some(window)).unwrap();
    assert!(a.is_commissionable());
    a.refresh([fabric(1)], None).unwrap();
    assert!(!a.is_commissionable());
}

#[test]
fn two_advertisers_draw_different_instance_names() {
    // §4.3.1.1: "a dynamic, pseudo-randomly selected, 64-bit temporary unique identifier". A
    // constant one is shared by every node built from the same code, and two of them on one link
    // make one unreachable.
    let a = advertiser(1);
    let b = advertiser(2);
    assert_ne!(a.instance(), b.instance());
    assert_ne!(a.host(), b.host());
    assert_eq!(a.instance().len(), 16);
}

#[test]
fn the_set_answers_a_browse() {
    let a = advertiser(1);
    let set = a.advertisements();
    let responder = Responder::new(&set);
    // A PTR query for _matterc._udp.local.
    let mut query = vec![0u8, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["_matterc", "_udp", "local"] {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 12, 0, 1]);
    let mut out = [0u8; 1280];
    let (_, answered) = responder.respond(&query, &mut out).expect("respond");
    assert!(!answered.is_empty());
}
