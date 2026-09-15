//! OTA Software Update Provider, cluster `0x0029` (Core §11.20.6).
//!
//! > This cluster implements the Provider role in the OTA process.
//!
//! A node that hands out firmware. An OTA Requestor asks "is there a newer image for this
//! vendor, product and version?", and the provider answers with a URI, a version and a token —
//! or with `NotAvailable`, or with `Busy` and a time to come back.
//!
//! # The provider decides, and the requestor obeys the delay
//!
//! §11.20.6.5's `DelayedActionTime` is the whole flow-control mechanism. A provider serving a
//! fleet cannot have every device download at once, and this is how it spreads them:
//!
//! > This field, if provided, SHALL convey the minimum time to wait, in seconds from the time
//! > of this response, before sending another QueryImage command or beginning a download.
//!
//! The same field appears in `ApplyUpdateResponse`, where it delays the *reboot* — which is
//! what stops every light in a house going dark at the same moment.
//!
//! # The image itself is not here
//!
//! A `QueryImageResponse` carries a URI, not bytes. §11.20.6.5's `bdx:` scheme names the node
//! and the file, and the transfer belongs to [`bdx`](crate::bdx) — a separate protocol on a
//! separate exchange. So a provider built on this cluster answers the query, and then
//! [`bdx::Sender`](crate::bdx::Sender) moves the image.
//!
//! [`ImageUri`] builds and parses the `bdx:` form, because §11.20.6.5 spends a page on its
//! syntax and gets specific about why: "the format constraints simplify the extraction of the
//! necessary data", and a requestor is entitled to rely on that.

use crate::clusters::generated::ota_software_update_provider as spec_ota;
use crate::dm::spec::{Conforming, Optional};
use crate::dm::{Resolved, ResolvedCommand};
use crate::im::{ClusterHandler, ClusterId, CommandId, InteractionContext, Status, StatusIb};
use crate::msg::{NodeId, VendorId};
use crate::tlv::{Tag, TlvWriter, ToTlv};

use super::Cluster;

pub use spec_ota::command::{
    APPLY_UPDATE_REQUEST, APPLY_UPDATE_RESPONSE, NOTIFY_UPDATE_APPLIED, QUERY_IMAGE,
    QUERY_IMAGE_RESPONSE,
};
pub use spec_ota::{ApplyUpdateActionEnum, DownloadProtocolEnum, ID, PICS, REVISION, StatusEnum};

/// §11.20.6.5's constraint on `UpdateToken`: "8 to 32".
pub const TOKEN_MIN: usize = 8;
/// The other end of it.
pub const TOKEN_MAX: usize = 32;

/// §11.20.6.5's constraint on `ImageURI`: "max 256".
pub const URI_MAX: usize = 256;

/// §11.20.6.5's constraint on `SoftwareVersionString`: "1 to 64".
pub const VERSION_STRING_MAX: usize = 64;

/// §11.20.6.5's ceiling on a useful `DelayedActionTime`.
///
/// > If this field has a value higher than 86400 seconds (24 hours), then the OTA Requestor MAY
/// > assume a value of 86400.
pub const MAX_USEFUL_DELAY_S: u32 = 86_400;

/// Which node is asking, and for what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Query {
    /// The requestor's `VendorID`, which §11.20.6.5 requires to match its Basic Information.
    pub vendor_id: VendorId,
    /// Its `ProductID`.
    pub product_id: u16,
    /// The version it is running now.
    pub software_version: u32,
    /// Its `HardwareVersion`, when it told us.
    pub hardware_version: Option<u16>,
    /// Whether the requestor can ask a person before applying an update.
    ///
    /// §11.20.3.4: a provider that requires consent may only set `UserConsentNeeded` when the
    /// requestor said it can obtain it — otherwise the update would stall for ever waiting for
    /// a confirmation nothing can give.
    pub requestor_can_consent: bool,
    /// Whether the requestor can take a synchronous BDX transfer.
    ///
    /// §11.20.6.5: "BDX Synchronous transfer mode SHALL always be supported by an OTA
    /// Provider", so a requestor that does not offer it is offering something else entirely.
    pub supports_bdx: bool,
    /// Whether it offered HTTPS.
    pub supports_https: bool,
}

/// What the provider has for a requestor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer<'a> {
    /// §11.20.6.4's `UpdateAvailable`: here it is.
    Available {
        /// Where to get it. `bdx:` names this provider and a file (§11.20.6.5).
        uri: &'a str,
        /// The version the image carries.
        software_version: u32,
        /// Its human-readable form, 1 to 64 characters.
        software_version_string: &'a str,
        /// §11.20.3.6.1's `UpdateToken`, 8 to 32 octets — the provider's handle on this
        /// particular update, which comes back in `ApplyUpdateRequest`.
        update_token: &'a [u8],
        /// Whether a person must confirm before the requestor applies it.
        user_consent_needed: bool,
    },
    /// `Busy`: there may be one, but not yet. Come back after `delay_s`.
    Busy {
        /// Seconds to wait, which §11.20.6.5 makes mandatory for this status.
        delay_s: u32,
    },
    /// `NotAvailable`: "there is definitely no update currently available".
    NotAvailable,
    /// `DownloadProtocolNotSupported`: there is an image, but not one this requestor can fetch.
    ProtocolNotSupported,
}

/// What the provider decides about a requestor that is ready to reboot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyDecision {
    /// Go ahead, wait, or give up.
    pub action: ApplyUpdateActionEnum,
    /// How long to wait first, in seconds.
    ///
    /// This is what staggers a fleet: a hundred lights told to reboot at once is a hundred
    /// lights dark at once.
    pub delay_s: u32,
}

impl ApplyDecision {
    /// Apply it now.
    #[must_use]
    pub const fn proceed() -> Self {
        Self {
            action: ApplyUpdateActionEnum::Proceed,
            delay_s: 0,
        }
    }

    /// Wait `delay_s` seconds, then ask again.
    #[must_use]
    pub const fn wait(delay_s: u32) -> Self {
        Self {
            action: ApplyUpdateActionEnum::AwaitNextAction,
            delay_s,
        }
    }

    /// §11.20.6.4's `Discontinue` — "a desire to rescind a previously provided Software Image".
    #[must_use]
    pub const fn discontinue() -> Self {
        Self {
            action: ApplyUpdateActionEnum::Discontinue,
            delay_s: 0,
        }
    }
}

/// What the product knows about the images it has.
pub trait OtaProviderHooks {
    /// §11.20.6.5's `QueryImage`: is there something newer for this device?
    ///
    /// The whole selection policy — which images exist, which hardware they suit, how a fleet
    /// is staggered — is the provider's, and none of it is derivable from the cluster.
    fn query(&self, query: &Query) -> Answer<'_>;

    /// §11.20.6.5's `ApplyUpdateRequest`: the requestor has the image and is ready to reboot.
    ///
    /// > The OTA Provider SHALL NOT refer to previously stored state about any download
    /// > progress to reply.
    ///
    /// The default proceeds, which is right for a provider with one device to update and wrong
    /// for one with a hundred.
    fn apply(&self, update_token: &[u8], new_version: u32) -> ApplyDecision {
        let _ = (update_token, new_version);
        ApplyDecision::proceed()
    }

    /// §11.20.6.5's `NotifyUpdateApplied` — it worked.
    ///
    /// > An OTA Provider SHALL NOT expect every OTA Requestor to invoke this command for
    /// > correct operation.
    ///
    /// A device that updated and then fell off the network never sends it, so a provider that
    /// waited for one would wait for ever.
    fn applied(&self, update_token: &[u8], software_version: u32) {
        let _ = (update_token, software_version);
    }
}

/// A `bdx:` image URI (§11.20.6.5).
///
/// §11.20.6.5 fixes the syntax hard — exactly 16 uppercase hexadecimal digits for the node id,
/// no user, no port, no query, no fragment — and then explains why: "the format constraints
/// simplify the extraction of the necessary data to reach the BDX server". A requestor is
/// entitled to parse it by position, so a provider that emitted `bdx://99AABBCCDDEE77/...`
/// with a leading zero dropped would produce a URI the specification's own worked example
/// calls invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageUri<'a> {
    /// The node to fetch from, which §11.20.6.5 requires to be the provider itself.
    pub node_id: NodeId,
    /// The file designator — "the path as received verbatim, after the first '/' following the
    /// host", with percent-escapes *not* decoded.
    pub file: &'a str,
}

impl<'a> ImageUri<'a> {
    /// The shortest valid `bdx:` URI: `bdx://` plus sixteen digits, a slash and one character.
    pub const MIN_LEN: usize = 24;

    /// Writes the URI into `buf`, returning the text.
    ///
    /// Refuses a file designator that would take the URI past §11.20.6.5's "max 256".
    pub fn write<'b>(&self, buf: &'b mut [u8]) -> crate::error::Result<&'b str> {
        let needed = 6usize
            .saturating_add(16)
            .saturating_add(1)
            .saturating_add(self.file.len());
        if needed > URI_MAX || needed > buf.len() {
            return Err(crate::Error::new(crate::ErrorCode::BufferTooSmall));
        }
        let mut at = 0usize;
        let mut put = |bytes: &[u8], at: &mut usize| {
            for byte in bytes {
                if let Some(slot) = buf.get_mut(*at) {
                    *slot = *byte;
                }
                *at = at.saturating_add(1);
            }
        };
        put(b"bdx://", &mut at);
        // "exactly 16 characters to encode the network byte order value of the NodeID", in
        // uppercase — §11.20.6.5's own invalid example is one with the leading zeros omitted.
        for shift in (0..16u32).rev().map(|nibble| nibble.saturating_mul(4)) {
            let nibble = u8::try_from((self.node_id.0 >> shift) & 0xF).unwrap_or(0);
            let digit = match nibble {
                0..=9 => b'0'.saturating_add(nibble),
                _ => b'A'.saturating_add(nibble.saturating_sub(10)),
            };
            put(&[digit], &mut at);
        }
        put(b"/", &mut at);
        put(self.file.as_bytes(), &mut at);
        let written = buf
            .get(..at)
            .ok_or_else(|| crate::Error::new(crate::ErrorCode::BufferTooSmall))?;
        core::str::from_utf8(written)
            .map_err(|_| crate::Error::new(crate::ErrorCode::InvalidArgument))
    }

    /// Reads §11.20.6.5's `bdx:` form, following its own worked procedure.
    pub fn parse(uri: &'a str) -> crate::error::Result<Self> {
        let invalid = || crate::Error::new(crate::ErrorCode::InvalidArgument);
        if uri.len() < Self::MIN_LEN {
            return Err(invalid());
        }
        let rest = uri.strip_prefix("bdx://").ok_or_else(invalid)?;
        let (host, file) = rest.split_at_checked(16).ok_or_else(invalid)?;
        let mut node = 0u64;
        for byte in host.bytes() {
            let nibble = match byte {
                b'0'..=b'9' => byte.saturating_sub(b'0'),
                // Uppercase only: §11.20.6.5 says "uppercase hexadecimal format", and a
                // requestor parsing by position has no reason to accept anything else.
                b'A'..=b'F' => byte.saturating_sub(b'A').saturating_add(10),
                _ => return Err(invalid()),
            };
            node = node
                .checked_mul(16)
                .and_then(|n| n.checked_add(u64::from(nibble)))
                .ok_or_else(invalid)?;
        }
        let file = file.strip_prefix('/').ok_or_else(invalid)?;
        if file.is_empty() || file.contains('?') || file.contains('#') {
            // "The URI SHALL NOT contain a query field" and "SHALL NOT contain a fragment".
            return Err(invalid());
        }
        Ok(Self {
            node_id: NodeId(node),
            file,
        })
    }
}

/// OTA Software Update Provider over a store of images.
#[derive(Debug)]
pub struct OtaProvider<'a, H: OtaProviderHooks> {
    hooks: &'a H,
}

impl<'a, H: OtaProviderHooks> OtaProvider<'a, H> {
    /// A provider over `hooks`.
    #[must_use]
    pub const fn new(hooks: &'a H) -> Self {
        Self { hooks }
    }

    /// The descriptor for an instance, derived from the specification's tables.
    ///
    /// §11.20.6.2 puts this cluster's scope at *node*, not endpoint — a provider is a role the
    /// node plays, not a thing one of its endpoints is.
    pub fn conforming(
        feature_map: u32,
        optional: &Optional<'_>,
    ) -> crate::error::Result<Conforming<0, 3, 2, 0>> {
        Conforming::new(&spec_ota::CLUSTER, feature_map, optional)
    }
}

impl<H: OtaProviderHooks> ClusterHandler for OtaProvider<'_, H> {
    fn read(
        &self,
        _resolved: &Resolved<'_>,
        _ctx: &InteractionContext<'_>,
        _w: &mut TlvWriter<'_>,
        _tag: Tag,
    ) -> Result<(), Status> {
        // §11.20.6 defines no attributes: a provider is all commands. Everything a client
        // could want to know is the answer to a query it has to make anyway.
        Err(Status::UnsupportedAttribute)
    }

    fn invoke(
        &self,
        resolved: &ResolvedCommand<'_>,
        fields: Option<&[u8]>,
        _ctx: &InteractionContext<'_>,
        w: &mut TlvWriter<'_>,
        tag: Tag,
    ) -> Result<Option<CommandId>, StatusIb> {
        let payload = || fields.ok_or(StatusIb::from(Status::InvalidCommand));
        let full = |r: crate::error::Result<()>| r.map_err(|_| StatusIb::from(Status::Failure));
        match resolved.command.id {
            QUERY_IMAGE => {
                let decoded: spec_ota::QueryImageFields<'_> = super::decode_fields(payload()?)?;
                let mut supports_bdx = false;
                let mut supports_https = false;
                for protocol in decoded.protocols_supported.iter() {
                    // §7.19.2: a protocol this revision does not define is one the provider
                    // cannot serve, which is not an error in the *request* — the requestor may
                    // legitimately know a newer one.
                    match protocol {
                        Ok(DownloadProtocolEnum::BDXSynchronous)
                        | Ok(DownloadProtocolEnum::BDXAsynchronous) => supports_bdx = true,
                        Ok(DownloadProtocolEnum::HTTPS) => supports_https = true,
                        _ => {}
                    }
                }
                let query = Query {
                    vendor_id: decoded.vendor_id,
                    product_id: decoded.product_id,
                    software_version: decoded.software_version,
                    hardware_version: decoded.hardware_version,
                    requestor_can_consent: decoded.requestor_can_consent.unwrap_or(false),
                    supports_bdx,
                    supports_https,
                };
                let answer = self.hooks.query(&query);
                let response = Self::response(&answer, &query)?;
                full(response.to_tlv(w, tag))?;
                Ok(Some(QUERY_IMAGE_RESPONSE))
            }
            APPLY_UPDATE_REQUEST => {
                let decoded: spec_ota::ApplyUpdateRequestFields<'_> =
                    super::decode_fields(payload()?)?;
                // §11.20.6.5's constraint on `UpdateToken` is "8 to 32". A token outside it is
                // not one this provider ever issued.
                if !(TOKEN_MIN..=TOKEN_MAX).contains(&decoded.update_token.len()) {
                    return Err(Status::ConstraintError.into());
                }
                let decision = self.hooks.apply(decoded.update_token, decoded.new_version);
                full(
                    spec_ota::ApplyUpdateResponseFields {
                        action: decision.action,
                        // §11.20.6.5: a requestor "MAY assume a value of 86400" for anything
                        // larger, so sending more is asking for a delay that will be ignored.
                        delayed_action_time: decision.delay_s.min(MAX_USEFUL_DELAY_S),
                    }
                    .to_tlv(w, tag),
                )?;
                Ok(Some(APPLY_UPDATE_RESPONSE))
            }
            NOTIFY_UPDATE_APPLIED => {
                let decoded: spec_ota::NotifyUpdateAppliedFields<'_> =
                    super::decode_fields(payload()?)?;
                if !(TOKEN_MIN..=TOKEN_MAX).contains(&decoded.update_token.len()) {
                    return Err(Status::ConstraintError.into());
                }
                self.hooks
                    .applied(decoded.update_token, decoded.software_version);
                // §11.20.6.5 gives it no response command: "An OTA Provider receiving an
                // invocation of this command MAY log it internally", and that is all.
                Ok(None)
            }
            _ => Err(Status::UnsupportedCommand.into()),
        }
    }
}

impl<H: OtaProviderHooks> OtaProvider<'_, H> {
    /// Builds `QueryImageResponse` from an [`Answer`], enforcing §11.20.6.5's conditional
    /// conformance.
    fn response<'r>(
        answer: &Answer<'r>,
        query: &Query,
    ) -> Result<spec_ota::QueryImageResponseFields<'r>, StatusIb> {
        let empty = spec_ota::QueryImageResponseFields {
            status: StatusEnum::NotAvailable,
            delayed_action_time: None,
            image_uri: None,
            software_version: None,
            software_version_string: None,
            update_token: None,
            user_consent_needed: None,
            metadata_for_requestor: None,
        };
        Ok(match *answer {
            Answer::NotAvailable => empty,
            Answer::ProtocolNotSupported => spec_ota::QueryImageResponseFields {
                status: StatusEnum::DownloadProtocolNotSupported,
                ..empty
            },
            Answer::Busy { delay_s } => spec_ota::QueryImageResponseFields {
                status: StatusEnum::Busy,
                // §11.20.6.5 makes it mandatory for `Busy`: without it the requestor has no
                // idea when to come back and will hammer the provider.
                delayed_action_time: Some(delay_s.min(MAX_USEFUL_DELAY_S)),
                ..empty
            },
            Answer::Available {
                uri,
                software_version,
                software_version_string,
                update_token,
                user_consent_needed,
            } => {
                if uri.len() > URI_MAX
                    || software_version_string.is_empty()
                    || software_version_string.len() > VERSION_STRING_MAX
                    || !(TOKEN_MIN..=TOKEN_MAX).contains(&update_token.len())
                {
                    return Err(Status::Failure.into());
                }
                // §11.20.3.4: consent may only be demanded of a requestor that said it can
                // obtain it. Demanding it of one that cannot stalls the update for ever waiting
                // for a confirmation nothing can give.
                let consent = user_consent_needed && query.requestor_can_consent;
                spec_ota::QueryImageResponseFields {
                    status: StatusEnum::UpdateAvailable,
                    delayed_action_time: None,
                    image_uri: Some(uri),
                    software_version: Some(software_version),
                    software_version_string: Some(software_version_string),
                    update_token: Some(update_token),
                    user_consent_needed: Some(consent),
                    metadata_for_requestor: None,
                }
            }
        })
    }
}

/// So a tuple of clusters can dispatch to it by id.
impl<H: OtaProviderHooks> Cluster for OtaProvider<'_, H> {
    const ID: ClusterId = ID;
}
