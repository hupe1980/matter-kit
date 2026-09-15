//! What a BLE stack needs to carry Matter: the GATT service, and the advertisement a
//! commissioner scans for (Core §4.19.4.2, §5.4.2.5).
//!
//! [`btp`](super::btp) is the protocol; this is its surface against the radio. Everything
//! here is data — identifiers and payload formats — because the API that drives a BLE
//! controller is where every platform differs, and a trait covering `nrf-softdevice`,
//! `esp32-nimble`, BlueZ and CoreBluetooth alike would fit none of them well.
//!
//! # The commissioner has to find the device without asking
//!
//! §5.4.2.5.6 explains why everything is in the advertisement rather than the scan response:
//!
//! > In order to reduce 2.4 GHz spectrum congestion due to active BLE scanning, and to extend
//! > battery life in battery-powered devices, all critical data used for device discovery is
//! > contained in the Advertising Data rather than the Scan Response Data.
//!
//! So a commissioner scanning passively already has the discriminator it needs to match a
//! device against a Setup Code, and never transmits at all.

use crate::bytes::Cursor;
use crate::commissioning::OnboardingPayload;
use crate::error::{ErrorCode, Result, bail};
use crate::msg::VendorId;

/// `0xFFF6` — `MATTER_BLE_SERVICE_UUID`, the 16-bit UUID the Bluetooth SIG assigned to Matter
/// (Core Table 36).
pub const SERVICE_UUID: u16 = 0xFFF6;

/// C1, the Client TX Buffer: `18EE2EF5-263D-4559-959F-4F9C429F9D11`, write-only.
///
/// "The client SHALL exclusively use C1 to initiate BTP sessions by sending BTP handshake
/// requests and send data to the server via GATT ATT_WRITE_REQ PDUs" (§4.19.4.2).
///
/// Written most-significant octet first, the order a UUID is printed in. A BLE stack that
/// wants the little-endian wire order reverses it.
pub const C1_UUID: [u8; 16] = [
    0x18, 0xEE, 0x2E, 0xF5, 0x26, 0x3D, 0x45, 0x59, 0x95, 0x9F, 0x4F, 0x9C, 0x42, 0x9F, 0x9D, 0x11,
];

/// C2, the Client RX Buffer: `18EE2EF5-263D-4559-959F-4F9C429F9D12`, indications only.
///
/// "While a client is subscribed to allow indications over C2, the server SHALL exclusively
/// use C2 to respond to BTP handshake requests and send data to the client via GATT
/// ATT_HANDLE_VALUE_IND PDUs" (§4.19.4.2). Unsubscribing from it is also how a client closes
/// a BTP session (§4.19.4.10).
pub const C2_UUID: [u8; 16] = [
    0x18, 0xEE, 0x2E, 0xF5, 0x26, 0x3D, 0x45, 0x59, 0x95, 0x9F, 0x4F, 0x9C, 0x42, 0x9F, 0x9D, 0x12,
];

/// C3, the optional additional commissioning data: `64630238-8772-45F2-B87D-748A83218F04`,
/// read-only, up to 512 octets (§4.19.4.2, §5.4.2.5.7).
pub const C3_UUID: [u8; 16] = [
    0x64, 0x63, 0x02, 0x38, 0x87, 0x72, 0x45, 0xF2, 0xB8, 0x7D, 0x74, 0x8A, 0x83, 0x21, 0x8F, 0x04,
];

/// The maximum length of C1 and C2, "imposed to align with maximum PDU size when LE Data
/// Packet Length Extensions (DPLE) is enabled on Bluetooth 4.2 hardware" (§4.19.4.2).
pub const CHARACTERISTIC_MAX: usize = 244;

/// `AD Type` 0x01 — Flags.
pub const AD_TYPE_FLAGS: u8 = 0x01;
/// `AD Type` 0x16 — Service Data, 16-bit UUID (Bluetooth CSS 12 §1.11).
pub const AD_TYPE_SERVICE_DATA: u8 = 0x16;

/// The GAP flags a commissionable device advertises: General Discoverable, BR/EDR not
/// supported (§5.4.2.5.4 — "Commissionable devices SHALL use the GAP General Discoverable
/// mode, sending connectable undirected advertising events").
pub const FLAGS_COMMISSIONABLE: u8 = 0x06;

/// The GAP flags a device in Network Recovery advertises: Limited Discoverable, BR/EDR not
/// supported (Core Table 75).
pub const FLAGS_RECOVERY: u8 = 0x05;

/// §5.4.2.5.6's Matter BLE Device OpCodes (Core Table 71).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OpCode {
    /// The device is advertising to be commissioned.
    Commissionable = 0x00,
    /// The device has lost its operational network and is advertising for recovery
    /// (§11.10.6.11's `RecoveryIdentifier`).
    NetworkRecovery = 0x01,
}

/// What a Matter BLE advertisement says (§5.4.2.5.6).
///
/// All multi-byte values are little-endian "within the service data payload", which is the
/// opposite of the UUID order two octets earlier in the same advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advertisement {
    /// Core Table 72 — a device waiting to be commissioned.
    Commissionable {
        /// §5.4.2.4.1's 12-bit discriminator, the value a Setup Code selects a device by.
        discriminator: u16,
        /// The Vendor ID, or [`VendorId`]`(0)` when elided.
        vendor_id: VendorId,
        /// The Product ID, or 0 when elided.
        product_id: u16,
        /// Whether C3 carries §5.4.2.5.7's GATT-based Additional Data.
        additional_data: bool,
        /// Whether the device is in its §5.4.2.3.3 Extended Announcement period. "SHALL NOT
        /// be set during the initial Announcement Duration."
        extended_announcement: bool,
    },
    /// Core Table 74 — a device that has lost its network.
    NetworkRecovery {
        /// §11.10.6.11's 64-bit `RecoveryIdentifier`.
        recovery_id: u64,
        /// Whether C3 carries additional data.
        additional_data: bool,
    },
}

impl Advertisement {
    /// The longest service data payload either form produces.
    pub const SERVICE_DATA_MAX: usize = 11;

    /// The longest complete advertising payload [`Advertisement::encode`] produces: the Flags
    /// structure, the Service Data header, and the payload.
    pub const MAX: usize = 3 + 4 + Self::SERVICE_DATA_MAX;

    /// The advertisement for a device whose label carries `payload`.
    ///
    /// The QR code and the BLE advertisement have to agree: a commissioner scans for the
    /// discriminator it read off the label, and a device advertising a different one is
    /// simply never found. Deriving one from the other is how they stay in step.
    #[must_use]
    pub const fn for_onboarding(payload: &OnboardingPayload) -> Self {
        Self::Commissionable {
            discriminator: payload.discriminator,
            vendor_id: payload.vendor_id,
            product_id: payload.product_id,
            additional_data: false,
            extended_announcement: false,
        }
    }

    /// Drops the vendor and product from a commissionable advertisement.
    ///
    /// §5.4.2.5.6: "Devices MAY choose not to advertise either the VID and PID … due to
    /// privacy or other considerations." Both go or neither does — a product without a
    /// vendor is forbidden, and [`Advertisement::encode`] refuses it.
    #[must_use]
    pub const fn elide_identity(self) -> Self {
        match self {
            Self::Commissionable {
                discriminator,
                additional_data,
                extended_announcement,
                ..
            } => Self::Commissionable {
                discriminator,
                vendor_id: VendorId(0),
                product_id: 0,
                additional_data,
                extended_announcement,
            },
            other => other,
        }
    }

    /// Marks C3 as carrying §5.4.2.5.7's GATT-based Additional Data.
    #[must_use]
    pub const fn with_additional_data(self, present: bool) -> Self {
        match self {
            Self::Commissionable {
                discriminator,
                vendor_id,
                product_id,
                extended_announcement,
                ..
            } => Self::Commissionable {
                discriminator,
                vendor_id,
                product_id,
                additional_data: present,
                extended_announcement,
            },
            Self::NetworkRecovery { recovery_id, .. } => Self::NetworkRecovery {
                recovery_id,
                additional_data: present,
            },
        }
    }

    /// Marks the device as being in its §5.4.2.3.3 Extended Announcement period.
    ///
    /// "SHALL be set while the device is in the Extended Announcement period and SHALL NOT be
    /// set during the initial Announcement Duration" — a commissioner reads it as "this
    /// device has been waiting a while", and a device that leaves it set from boot says
    /// something untrue about itself.
    #[must_use]
    pub const fn with_extended_announcement(self, extended: bool) -> Self {
        match self {
            Self::Commissionable {
                discriminator,
                vendor_id,
                product_id,
                additional_data,
                ..
            } => Self::Commissionable {
                discriminator,
                vendor_id,
                product_id,
                additional_data,
                extended_announcement: extended,
            },
            other => other,
        }
    }

    /// The OpCode this form carries.
    #[must_use]
    pub const fn opcode(&self) -> OpCode {
        match self {
            Self::Commissionable { .. } => OpCode::Commissionable,
            Self::NetworkRecovery { .. } => OpCode::NetworkRecovery,
        }
    }

    /// Writes just the service data payload — the part after the `0xFFF6` UUID.
    ///
    /// Useful where the BLE stack assembles the AD structures itself, which most of them do.
    pub fn encode_service_data(&self, out: &mut [u8]) -> Result<usize> {
        match *self {
            Self::Commissionable {
                discriminator,
                vendor_id,
                product_id,
                additional_data,
                extended_announcement,
            } => {
                if discriminator > 0x0FFF {
                    // "Bits[15:12] == 0x0 (Advertisement version)" leaves twelve for the
                    // discriminator, and a wider value would silently become a version.
                    bail!(InvalidArgument)
                }
                if vendor_id.0 == 0 && product_id != 0 {
                    // "A device SHALL NOT set the VID to 0 when providing a non-zero PID."
                    bail!(InvalidArgument)
                }
                let mut w = Cursor::writer(out);
                w.u8(OpCode::Commissionable as u8)?;
                // The advertisement version occupies bits[15:12] and is zero, so the
                // discriminator goes out as-is.
                w.u16(discriminator)?;
                w.u16(vendor_id.0)?;
                w.u16(product_id)?;
                w.u8(u8::from(additional_data) | (u8::from(extended_announcement) << 1))?;
                Ok(w.position())
            }
            Self::NetworkRecovery {
                recovery_id,
                additional_data,
            } => {
                let mut w = Cursor::writer(out);
                w.u8(OpCode::NetworkRecovery as u8)?;
                w.u8(0)?; // Advertisement version and reserved, both zero.
                w.u64(recovery_id)?;
                w.u8(u8::from(additional_data))?;
                Ok(w.position())
            }
        }
    }

    /// Writes the complete advertising payload: the Flags AD structure followed by the
    /// Service Data one, as Core Tables 73 and 75 lay them out.
    ///
    /// A conformant advertisement may order its AD structures differently — "there are no
    /// ordering constraints for advertisement fields in the Length-Type-Value format used in
    /// BLE advertisements" — but this order is the one the specification's own examples use.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let flags = match self {
            Self::Commissionable { .. } => FLAGS_COMMISSIONABLE,
            Self::NetworkRecovery { .. } => FLAGS_RECOVERY,
        };
        // The service data goes into a scratch buffer first, because AD[1]'s length octet
        // comes before the payload it measures.
        let mut payload = [0u8; Self::SERVICE_DATA_MAX];
        let n = self.encode_service_data(&mut payload)?;
        let (Some(body), Ok(length)) = (payload.get(..n), u8::try_from(n.saturating_add(3))) else {
            // The type octet, the two UUID octets, and the payload.
            bail!(BufferTooSmall)
        };

        let mut w = Cursor::writer(out);
        w.u8(2)?; // AD[0] length: the type octet plus the flags octet.
        w.u8(AD_TYPE_FLAGS)?;
        w.u8(flags)?;
        w.u8(length)?;
        w.u8(AD_TYPE_SERVICE_DATA)?;
        w.u16(SERVICE_UUID)?;
        w.put(body)?;
        Ok(w.position())
    }

    /// Reads a service data payload — the octets a scanner finds under UUID `0xFFF6`.
    ///
    /// This is a commissioner's half of the protocol: it turns a passive scan result into
    /// something that can be matched against a Setup Code's discriminator.
    pub fn decode_service_data(buf: &[u8]) -> Result<Self> {
        let mut r = Cursor::reader(buf, ErrorCode::BtpMalformed);
        match r.read_u8()? {
            0x00 => {
                let versioned = r.read_u16()?;
                if versioned >> 12 != 0 {
                    // An advertisement version this crate does not know: its remaining fields
                    // may mean something else entirely.
                    bail!(UnsupportedVersion)
                }
                let vendor_id = VendorId(r.read_u16()?);
                let product_id = r.read_u16()?;
                let flags = r.read_u8()?;
                Ok(Self::Commissionable {
                    discriminator: versioned & 0x0FFF,
                    vendor_id,
                    product_id,
                    additional_data: flags & 0x01 != 0,
                    extended_announcement: flags & 0x02 != 0,
                })
            }
            0x01 => {
                if r.read_u8()? >> 4 != 0 {
                    bail!(UnsupportedVersion)
                }
                let recovery_id = r.read_u64()?;
                Ok(Self::NetworkRecovery {
                    recovery_id,
                    additional_data: r.read_u8()? & 0x01 != 0,
                })
            }
            // "0x02 - 0xFF  Reserved".
            _ => bail!(UnsupportedVersion),
        }
    }

    /// Finds and reads the Matter service data inside a complete advertising payload.
    ///
    /// Walks the length-type-value structures looking for Service Data under
    /// [`SERVICE_UUID`], because a real advertisement carries other structures too and puts
    /// them in whatever order it likes.
    pub fn decode(advertisement: &[u8]) -> Result<Self> {
        let mut r = Cursor::reader(advertisement, ErrorCode::BtpMalformed);
        // Running out of structures is "no Matter device here"; a structure whose declared
        // length runs off the end is a malformed advertisement.
        while let Ok(length) = r.read_u8() {
            if length == 0 {
                // A zero length terminates the advertising data early (Bluetooth Core Spec
                // Vol 3 Part C §11), and the rest is padding.
                break;
            }
            let mut structure =
                Cursor::reader(r.take(usize::from(length))?, ErrorCode::BtpMalformed);
            if structure.read_u8() == Ok(AD_TYPE_SERVICE_DATA)
                && structure.read_u16() == Ok(SERVICE_UUID)
            {
                return Self::decode_service_data(structure.rest());
            }
        }
        bail!(TlvNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_commissionable_advertisement_matches_table_73() {
        // The specification's own worked example: VID 0xFFF1, PID 0x8000, discriminator 0x3AB,
        // additional data present. Byte-for-byte, because a commissioner matches on these.
        let advert = Advertisement::Commissionable {
            discriminator: 0x3AB,
            vendor_id: VendorId(0xFFF1),
            product_id: 0x8000,
            additional_data: true,
            extended_announcement: false,
        };
        let mut buf = [0u8; Advertisement::MAX];
        let n = advert.encode(&mut buf).expect("encode");
        assert_eq!(
            &buf[..n],
            &[
                0x02, 0x01, 0x06, // Flags: General Discoverable, BR/EDR not supported
                0x0B, 0x16, 0xF6, 0xFF, // Service Data, 16-bit UUID 0xFFF6
                0x00, // Commissionable
                0xAB, 0x03, // version 0, discriminator 0x3AB
                0xF1, 0xFF, // Vendor ID
                0x00, 0x80, // Product ID
                0x01, // additional data present
            ]
        );
        assert_eq!(Advertisement::decode(&buf[..n]).expect("decode"), advert);
    }

    #[test]
    fn a_network_recovery_advertisement_matches_table_75() {
        let advert = Advertisement::NetworkRecovery {
            // "the octet string 0x11 0x22 … 0x88", little-endian in the payload.
            recovery_id: u64::from_le_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
            additional_data: false,
        };
        let mut buf = [0u8; Advertisement::MAX];
        let n = advert.encode(&mut buf).expect("encode");
        assert_eq!(
            &buf[..n],
            &[
                0x02, 0x01, 0x05, // Flags: Limited Discoverable, BR/EDR not supported
                0x0E, 0x16, 0xF6, 0xFF, 0x01, // Network Recovery
                0x00, // version and reserved
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00,
            ]
        );
        assert_eq!(Advertisement::decode(&buf[..n]).expect("decode"), advert);
    }

    #[test]
    fn the_service_data_is_found_wherever_it_sits() {
        // "the position of the fields within the Advertising PDU … MAY differ from the
        // example above, since there are no ordering constraints" — so a scanner that assumed
        // a fixed offset would miss conformant devices.
        let advert = Advertisement::Commissionable {
            discriminator: 0xFFF,
            vendor_id: VendorId(0xFFF1),
            product_id: 0x8001,
            additional_data: false,
            extended_announcement: true,
        };
        let mut service_data = [0u8; 16];
        let n = advert
            .encode_service_data(&mut service_data)
            .expect("encode");

        let mut payload = heapless::Vec::<u8, 64>::new();
        // A Complete Local Name first, then some other Service Data, then Matter's.
        payload
            .extend_from_slice(&[0x05, 0x09, b'l', b'a', b'm', b'p'])
            .expect("name");
        payload
            .extend_from_slice(&[0x04, 0x16, 0x0F, 0x18, 0x64])
            .expect("battery");
        payload
            .extend_from_slice(&[u8::try_from(n + 3).expect("fits"), 0x16, 0xF6, 0xFF])
            .expect("header");
        payload
            .extend_from_slice(&service_data[..n])
            .expect("service data");

        assert_eq!(Advertisement::decode(&payload).expect("decode"), advert);
    }

    #[test]
    fn an_advertisement_with_no_matter_service_data_is_not_a_matter_device() {
        let other = [0x05u8, 0x09, b'l', b'a', b'm', b'p'];
        assert_eq!(
            Advertisement::decode(&other).map_err(|e| e.code()),
            Err(crate::ErrorCode::TlvNotFound)
        );
    }

    #[test]
    fn a_truncated_ad_structure_is_refused() {
        // A scanner takes these from the air; a length field longer than the buffer is the
        // first thing a malformed or clipped advertisement gets wrong.
        let clipped = [0x0Bu8, 0x16, 0xF6, 0xFF, 0x00];
        assert_eq!(
            Advertisement::decode(&clipped).map_err(|e| e.code()),
            Err(crate::ErrorCode::BtpMalformed)
        );
    }

    #[test]
    fn a_discriminator_wider_than_twelve_bits_is_refused() {
        // Bits[15:12] are the advertisement version. A 13-bit discriminator would advertise
        // version 1 and be discarded by every commissioner.
        let bad = Advertisement::Commissionable {
            discriminator: 0x1000,
            vendor_id: VendorId(0xFFF1),
            product_id: 0x8000,
            additional_data: false,
            extended_announcement: false,
        };
        let mut buf = [0u8; Advertisement::MAX];
        assert_eq!(
            bad.encode(&mut buf).map_err(|e| e.code()),
            Err(crate::ErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn a_product_id_without_a_vendor_id_is_refused() {
        // "A device SHALL NOT set the VID to 0 when providing a non-zero PID." Eliding both is
        // allowed; eliding only the vendor is not.
        let bad = Advertisement::Commissionable {
            discriminator: 0x3AB,
            vendor_id: VendorId(0),
            product_id: 0x8000,
            additional_data: false,
            extended_announcement: false,
        };
        let mut buf = [0u8; Advertisement::MAX];
        assert_eq!(
            bad.encode(&mut buf).map_err(|e| e.code()),
            Err(crate::ErrorCode::InvalidArgument)
        );

        let elided = Advertisement::Commissionable {
            discriminator: 0x3AB,
            vendor_id: VendorId(0),
            product_id: 0,
            additional_data: false,
            extended_announcement: false,
        };
        elided.encode(&mut buf).expect("eliding both is allowed");
    }

    #[test]
    fn a_reserved_opcode_is_not_guessed_at() {
        // "0x02 - 0xFF  Reserved". A future opcode's fields mean something this crate does not
        // know, so reading them as a discriminator would hand the commissioner a wrong device.
        assert_eq!(
            Advertisement::decode_service_data(&[0x02, 0, 0, 0, 0, 0, 0, 0]).map_err(|e| e.code()),
            Err(crate::ErrorCode::UnsupportedVersion)
        );
    }

    #[test]
    fn the_advertisement_and_the_qr_code_agree_on_the_discriminator() {
        // A device that advertises a different discriminator from the one on its label is
        // never found, and the failure looks like a radio problem rather than a wrong number.
        use crate::commissioning::{CustomFlow, DiscoveryCapabilities, Passcode};

        let payload = OnboardingPayload::new(
            VendorId(0xFFF1),
            0x8000,
            0x3AB,
            Passcode::new(20_202_021).expect("passcode"),
            DiscoveryCapabilities::BLE,
            CustomFlow::Standard,
        )
        .expect("payload");

        let advert = Advertisement::for_onboarding(&payload);
        let mut buf = [0u8; Advertisement::MAX];
        let n = advert.encode(&mut buf).expect("encode");
        let Advertisement::Commissionable {
            discriminator,
            vendor_id,
            product_id,
            ..
        } = Advertisement::decode(&buf[..n]).expect("decode")
        else {
            panic!("a commissionable advertisement")
        };
        assert_eq!(discriminator, payload.discriminator);
        assert_eq!(vendor_id, payload.vendor_id);
        assert_eq!(product_id, payload.product_id);

        // Eliding takes both halves of the identity, never one.
        let private = advert.elide_identity().with_extended_announcement(true);
        let n = private.encode(&mut buf).expect("encode");
        assert_eq!(Advertisement::decode(&buf[..n]).expect("decode"), private);
        let Advertisement::Commissionable {
            discriminator,
            vendor_id,
            product_id,
            extended_announcement,
            ..
        } = private
        else {
            panic!("still commissionable")
        };
        assert_eq!(discriminator, 0x3AB, "the discriminator is what finds it");
        assert_eq!((vendor_id, product_id), (VendorId(0), 0));
        assert!(extended_announcement);
    }

    #[test]
    fn the_characteristic_uuids_are_the_ones_in_table_34() {
        // Printed order, most-significant octet first. A stack wanting little-endian reverses.
        assert_eq!(&C1_UUID[12..], &[0x42, 0x9F, 0x9D, 0x11]);
        assert_eq!(&C2_UUID[12..], &[0x42, 0x9F, 0x9D, 0x12]);
        assert_eq!(
            C1_UUID[..12],
            C2_UUID[..12],
            "C1 and C2 differ in one nibble"
        );
        assert_eq!(C3_UUID[0], 0x64);
    }
}
