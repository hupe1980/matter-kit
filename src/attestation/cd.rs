//! The Certification Declaration (Core §6.3).
//!
//! A CD is the Connectivity Standards Alliance's signed statement that a device type passed
//! certification: "Upon successful completion of certification by a device type, Connectivity
//! Standards Alliance creates the CD for that device type so that it can be included in the
//! device firmware by the manufacturer."
//!
//! It is the one place Matter uses CMS. The outer wrapper is an RFC 5652 `SignedData`; the
//! content inside it is ordinary Matter TLV. So reading one is two parsers stacked:
//! [`SignedData::parse`] peels the CMS, [`CertificationElements::decode`] reads the TLV.
//!
//! # What the signature covers
//!
//! The `SignerInfo` here carries no `signedAttrs`, and RFC 5652 §5.4 is explicit about what
//! that means: with signed attributes absent, the signature is computed over the
//! **eContent octets themselves**, not over a DER-encoded attribute set. So verification is
//! `Crypto_Verify(CSA key, eContent, signature)` — and `eContent` is exactly the TLV
//! [`SignedData::content`] hands back.
//!
//! Getting that wrong is the classic CMS mistake, and it fails in a way that looks like a
//! bad key rather than a bad parse.
//!
//! # Who signs it
//!
//! §6.3.1 rule 5: "The subjectKeyIdentifier SHALL contain the subject key identifier (SKI)
//! of a well-known Connectivity Standards Alliance certificate". So a CD does not carry the
//! certificate that signed it — only a 20-octet hint. A commissioner looks the key up in a
//! store it already trusts, which is why [`SignedData::signer_key_id`] is exposed and why
//! verification takes a public key rather than finding one.

use heapless::Vec;

use crate::crypto::{PublicKey, Signature, verify};
use crate::der::{
    DerReader, OID_ECDSA_WITH_SHA256, OID_PKCS7_DATA, OID_SHA256, OID_SIGNED_DATA,
    TAG_OCTET_STRING, TAG_SEQUENCE, TAG_SET, context_constructed, context_primitive,
    ecdsa_sig_value_to_raw,
};
use crate::error::{Error, ErrorCode, Result, bail};
use crate::msg::VendorId;
use crate::tlv::{ContainerKind, Tag, TlvReader, TlvWriter, Value, set_once};

/// `\[0\]` constructed — `content [0] EXPLICIT` in a `ContentInfo`, and `eContent [0]`.
const TAG_EXPLICIT_0: u8 = context_constructed(0);
/// `\[0\]` primitive — `subjectKeyIdentifier [0] IMPLICIT` in a `SignerIdentifier`.
const TAG_SKI: u8 = context_primitive(0);

/// "The format SHALL only support CMS version v3" (§6.3.1 rule 1).
pub const CMS_VERSION: u64 = 3;

/// A Subject Key Identifier is 20 octets — the SHA-1 length of RFC 5280's method (1).
pub const KEY_ID_LEN: usize = 20;

/// "product_id_array \[2\] : ARRAY \[ length 1..100 \]" (§6.3.1).
pub const MAX_PRODUCT_IDS: usize = 100;

/// "authorized_paa_list \[11, optional\] : ARRAY \[ length 1..10 \]" (§6.3.1).
pub const MAX_AUTHORIZED_PAAS: usize = 10;

/// "certificate_id \[4\] : STRING \[ length 19 \]" (§6.3.1).
pub const CERTIFICATE_ID_LEN: usize = 19;

/// The largest Certification Declaration this crate will parse.
///
/// 100 product ids, ten PAA identifiers and the fixed fields, plus the CMS wrapper. The
/// specification sets no explicit cap; this one is derived from the field limits it does
/// set, so a declaration that fits the schema fits here.
pub const MAX_CD_LEN: usize = 1024;

fn malformed() -> Error {
    Error::new(ErrorCode::DerMalformed)
}

/// What kind of certification a declaration attests to (§6.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CertificationType {
    /// `0` — "used for development and test purposes".
    DevelopmentAndTest,
    /// `1` — "provisional - used to allow production and distribution to occur in parallel
    /// with certification". A product may ship with one "if the Certification Declaration
    /// can be replaced via software update".
    Provisional,
    /// `2` — "official - allocated after passing certification".
    Official,
    /// Anything else; the specification says "reserved".
    Reserved(u8),
}

impl CertificationType {
    /// The value a declaration carries.
    #[must_use]
    pub const fn from_value(value: u8) -> Self {
        match value {
            0 => Self::DevelopmentAndTest,
            1 => Self::Provisional,
            2 => Self::Official,
            other => Self::Reserved(other),
        }
    }

    /// The encoded value.
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::DevelopmentAndTest => 0,
            Self::Provisional => 1,
            Self::Official => 2,
            Self::Reserved(v) => v,
        }
    }
}

/// `certification-elements` — the TLV inside a CD's `eContent` (§6.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificationElements<'a> {
    /// `format_version \[0\]`. "SHALL contain the value 1."
    pub format_version: u16,
    /// `vendor_id \[1\]`.
    pub vendor_id: VendorId,
    /// `product_id_array \[2\]` — "a number of Product IDs which are covered by the same
    /// certification (e.g. certification by similarity)".
    pub product_ids: Vec<u16, MAX_PRODUCT_IDS>,
    /// `device_type_id \[3\]` — "the device type identifier for the primary function".
    pub device_type_id: u32,
    /// `certificate_id \[4\]` — "a globally unique serial number allocated by the Connectivity
    /// Standards Alliance".
    pub certificate_id: &'a str,
    /// `security_level \[5\]`. "Reserved for future use and SHALL be ignored at read time."
    pub security_level: u8,
    /// `security_information \[6\]`. Also reserved and ignored.
    pub security_information: u16,
    /// `version_number \[7\]` — the CD's own version, assigned by the CSA.
    pub version_number: u16,
    /// `certification_type \[8\]`.
    pub certification_type: CertificationType,
    /// `dac_origin_vendor_id \[9\]` — present only together with the product id.
    pub dac_origin_vendor_id: Option<VendorId>,
    /// `dac_origin_product_id \[10\]`.
    pub dac_origin_product_id: Option<u16>,
    /// `authorized_paa_list \[11\]` — the Subject Key Identifiers of the PAAs allowed to root
    /// this product's DAC chain.
    pub authorized_paas: Option<Vec<[u8; KEY_ID_LEN], MAX_AUTHORIZED_PAAS>>,
}

impl<'a> CertificationElements<'a> {
    /// Decodes the TLV of a `eContent`.
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        let mut reader = TlvReader::new(buf);
        let Some(head) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if head.value.container() != Some(ContainerKind::Structure) || !head.tag.is_anonymous() {
            bail!(TlvWrongType)
        }

        let mut format_version = None;
        let mut vendor_id = None;
        let mut product_ids = Vec::new();
        let mut has_product_ids = false;
        let mut device_type_id = None;
        let mut certificate_id = None;
        let mut security_level = None;
        let mut security_information = None;
        let mut version_number = None;
        let mut certification_type = None;
        let mut dac_origin_vendor_id = None;
        let mut dac_origin_product_id = None;
        let mut authorized_paas = None;

        loop {
            let Some(element) = reader.next_element()? else {
                bail!(TlvTruncated)
            };
            if element.value == Value::EndOfContainer {
                break;
            }
            let Some(tag) = element.tag.context() else {
                bail!(TlvInvalidTag)
            };
            match tag {
                0 => set_once(&mut format_version, narrow_u16(element.unsigned()?)?)?,
                1 => set_once(&mut vendor_id, VendorId(narrow_u16(element.unsigned()?)?))?,
                2 => {
                    if element.value.container() != Some(ContainerKind::Array) {
                        bail!(TlvWrongType)
                    }
                    if has_product_ids {
                        bail!(TlvDuplicateTag)
                    }
                    has_product_ids = true;
                    read_u16_array(&mut reader, &mut product_ids)?;
                }
                3 => {
                    let value = u32::try_from(element.unsigned()?)
                        .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))?;
                    set_once(&mut device_type_id, value)?;
                }
                4 => {
                    let text = element.utf8()?;
                    // "certificate_id [4] : STRING [ length 19 ]" — a fixed length, so a
                    // different one is a malformed declaration rather than a short id.
                    if text.len() != CERTIFICATE_ID_LEN {
                        bail!(TlvOutOfRange)
                    }
                    set_once(&mut certificate_id, text)?;
                }
                5 => {
                    let value = u8::try_from(element.unsigned()?)
                        .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))?;
                    set_once(&mut security_level, value)?;
                }
                6 => set_once(&mut security_information, narrow_u16(element.unsigned()?)?)?,
                7 => set_once(&mut version_number, narrow_u16(element.unsigned()?)?)?,
                8 => {
                    let value = CertificationType::from_value(
                        u8::try_from(element.unsigned()?)
                            .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))?,
                    );
                    set_once(&mut certification_type, value)?;
                }
                9 => {
                    set_once(
                        &mut dac_origin_vendor_id,
                        VendorId(narrow_u16(element.unsigned()?)?),
                    )?;
                }
                10 => set_once(&mut dac_origin_product_id, narrow_u16(element.unsigned()?)?)?,
                11 => {
                    if element.value.container() != Some(ContainerKind::Array) {
                        bail!(TlvWrongType)
                    }
                    set_once(&mut authorized_paas, read_key_id_array(&mut reader)?)?;
                }
                // "Any context-specific tags not listed in the above schema for
                // Certification Elements SHALL be reserved for future use, and SHALL be
                // silently ignored if seen by a Commissioner which cannot understand them."
                _ => reader.skip_value(&element)?,
            }
        }
        reader.finish()?;

        if !has_product_ids || product_ids.is_empty() {
            // `ARRAY [ length 1.. ]`.
            bail!(TlvNotFound)
        }
        // "The dac_origin_vendor_id and dac_origin_product_id SHALL only be present
        // together" — and §6.2.3.1 makes a declaration "valid only if it contains both or
        // neither".
        if dac_origin_vendor_id.is_some() != dac_origin_product_id.is_some() {
            bail!(TlvNotFound)
        }

        Ok(Self {
            format_version: format_version.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            vendor_id: vendor_id.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            product_ids,
            device_type_id: device_type_id.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            certificate_id: certificate_id.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            security_level: security_level.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            security_information: security_information.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            version_number: version_number.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            certification_type: certification_type.ok_or(Error::new(ErrorCode::TlvNotFound))?,
            dac_origin_vendor_id,
            dac_origin_product_id,
            authorized_paas,
        })
    }

    /// Encodes the TLV, in the `[tag-order]` the schema requires.
    ///
    /// A node never generates a CD — "Certification Declarations SHALL NOT be generated by
    /// any Node" — so this exists for a test harness, a factory tool, and for proving the
    /// decoder against the specification's vectors by round trip.
    ///
    /// **This output is not what a signature is checked against**, and that is deliberate.
    /// The CMS signature covers the `eContent` octets exactly as they arrived, and
    /// [`SignedData::content`] is a borrow of them rather than a re-encoding — so the one
    /// thing this encoder normalises, integer width, can never reach a verification. Matter
    /// TLV admits several widths for the same value and this writes the narrowest; the
    /// specification's own declarations are already minimal and re-encode byte for byte.
    pub fn encode<'b>(&self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        let mut w = TlvWriter::new(buf);
        w.start_structure(Tag::Anonymous)?;
        w.unsigned(Tag::Context(0), u64::from(self.format_version))?;
        w.unsigned(Tag::Context(1), u64::from(self.vendor_id.0))?;
        w.start_array(Tag::Context(2))?;
        for pid in &self.product_ids {
            w.unsigned(Tag::Anonymous, u64::from(*pid))?;
        }
        w.end_container()?;
        w.unsigned(Tag::Context(3), u64::from(self.device_type_id))?;
        w.utf8(Tag::Context(4), self.certificate_id)?;
        w.unsigned(Tag::Context(5), u64::from(self.security_level))?;
        w.unsigned(Tag::Context(6), u64::from(self.security_information))?;
        w.unsigned(Tag::Context(7), u64::from(self.version_number))?;
        w.unsigned(Tag::Context(8), u64::from(self.certification_type.value()))?;
        if let Some(vid) = self.dac_origin_vendor_id {
            w.unsigned(Tag::Context(9), u64::from(vid.0))?;
        }
        if let Some(pid) = self.dac_origin_product_id {
            w.unsigned(Tag::Context(10), u64::from(pid))?;
        }
        if let Some(paas) = self.authorized_paas.as_ref() {
            w.start_array(Tag::Context(11))?;
            for ski in paas {
                w.octets(Tag::Anonymous, ski)?;
            }
            w.end_container()?;
        }
        w.end_container()?;
        w.finish()
    }

    /// Whether `product_id` is one of those this declaration covers.
    #[must_use]
    pub fn covers_product(&self, product_id: u16) -> bool {
        self.product_ids.contains(&product_id)
    }

    /// Whether `ski` is an authorised PAA, or the declaration does not restrict them.
    ///
    /// §6.2.3.1: "If the Certification Declaration contains the authorized_paa_list field …
    /// The Subject Key Identifier (SKI) extension value of the PAA certificate, which is the
    /// root of trust of the DAC, SHALL be present as one of the values". An absent list
    /// authorises any PAA the commissioner already trusts.
    #[must_use]
    pub fn authorizes_paa(&self, ski: &[u8; KEY_ID_LEN]) -> bool {
        self.authorized_paas
            .as_ref()
            .is_none_or(|list| list.contains(ski))
    }
}

fn narrow_u16(value: u64) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::new(ErrorCode::TlvOutOfRange))
}

fn read_u16_array(reader: &mut TlvReader<'_>, out: &mut Vec<u16, MAX_PRODUCT_IDS>) -> Result<()> {
    loop {
        let Some(element) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if element.value == Value::EndOfContainer {
            return Ok(());
        }
        if !element.tag.is_anonymous() {
            bail!(TlvInvalidTag)
        }
        out.push(narrow_u16(element.unsigned()?)?)
            .map_err(|_| Error::new(ErrorCode::NoSpace))?;
    }
}

fn read_key_id_array(
    reader: &mut TlvReader<'_>,
) -> Result<Vec<[u8; KEY_ID_LEN], MAX_AUTHORIZED_PAAS>> {
    let mut out = Vec::new();
    loop {
        let Some(element) = reader.next_element()? else {
            bail!(TlvTruncated)
        };
        if element.value == Value::EndOfContainer {
            if out.is_empty() {
                // `ARRAY [ length 1..10 ]`.
                bail!(TlvNotFound)
            }
            return Ok(out);
        }
        if !element.tag.is_anonymous() {
            bail!(TlvInvalidTag)
        }
        let ski = <[u8; KEY_ID_LEN]>::try_from(element.octets()?)
            .map_err(|_| Error::new(ErrorCode::TlvOutOfRange))?;
        out.push(ski).map_err(|_| Error::new(ErrorCode::NoSpace))?;
    }
}

/// A parsed CMS `SignedData` carrying a Certification Declaration (RFC 5652 §5).
///
/// Only the profile §6.3.1 permits is accepted: version 3, a single SHA-256 digest
/// algorithm, `pkcs7-data` content, one signer identified by Subject Key Identifier, and
/// ECDSA-with-SHA256. Anything broader would be a parser for CMS rather than for a CD, with
/// a correspondingly larger attack surface for no benefit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedData<'a> {
    /// The `eContent` octets — the TLV of [`CertificationElements`], and the exact bytes the
    /// signature covers.
    pub content: &'a [u8],
    /// The signer's Subject Key Identifier, which names a CSA key the commissioner must
    /// already hold.
    pub signer_key_id: [u8; KEY_ID_LEN],
    /// The signature, converted from the DER `ECDSA-Sig-Value` to the `r || s` of §3.5.3.
    pub signature: Signature,
}

impl<'a> SignedData<'a> {
    /// Parses a CD.
    pub fn parse(der: &'a [u8]) -> Result<Self> {
        if der.len() > MAX_CD_LEN {
            return Err(malformed());
        }
        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        let mut outer = DerReader::new(der);
        let mut content_info = outer.expect_sequence()?;
        outer.finish()?;
        content_info.expect_oid(OID_SIGNED_DATA)?;
        let mut explicit = content_info.expect(TAG_EXPLICIT_0)?.content_reader();
        content_info.finish()?;

        // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
        //                           certificates [0] OPTIONAL, crls [1] OPTIONAL,
        //                           signerInfos }
        let mut signed = explicit.expect_sequence()?;
        explicit.finish()?;
        if signed.expect_uint()? != CMS_VERSION {
            return Err(malformed());
        }

        // digestAlgorithms: exactly one, sha256.
        let mut digests = signed.expect_set()?;
        let mut digest = digests.expect_sequence()?;
        digest.expect_oid(OID_SHA256)?;
        // An AlgorithmIdentifier may carry parameters; sha256's are absent or NULL, and
        // neither changes anything, so whatever is there is skipped rather than refused.
        digests.finish()?;

        // encapContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET
        //                                 STRING OPTIONAL }
        let mut encap = signed.expect_sequence()?;
        encap.expect_oid(OID_PKCS7_DATA)?;
        let mut econtent = encap.expect(TAG_EXPLICIT_0)?.content_reader();
        let content = econtent.expect(TAG_OCTET_STRING)?.content;
        econtent.finish()?;
        encap.finish()?;

        // certificates [0] and crls [1] are optional and not used by a CD; §6.3.1 names the
        // signer by key identifier instead. Skipping rather than refusing keeps a
        // declaration that carries its certificate readable.
        let _ = signed.take_if(context_constructed(0))?;
        let _ = signed.take_if(context_constructed(1))?;

        // signerInfos: exactly one.
        let mut signers = signed.expect(TAG_SET)?.content_reader();
        signed.finish()?;
        let mut signer = signers.expect_sequence()?;
        // "there SHALL be exactly one signer" is implied by §6.3.1's single
        // subjectKeyIdentifier rule; a second signer would leave it ambiguous which key
        // verified the declaration.
        signers.finish()?;

        if signer.expect_uint()? != CMS_VERSION {
            return Err(malformed());
        }
        // SignerIdentifier ::= CHOICE { issuerAndSerialNumber, subjectKeyIdentifier [0] }.
        // §6.3.1 rule 5 requires the second.
        let signer_key_id = <[u8; KEY_ID_LEN]>::try_from(signer.expect(TAG_SKI)?.content)
            .map_err(|_| malformed())?;

        let mut signer_digest = signer.expect_sequence()?;
        signer_digest.expect_oid(OID_SHA256)?;

        // signedAttrs [0] IMPLICIT. Its presence changes what the signature covers — see the
        // module documentation — so it is refused rather than ignored.
        if signer.peek_tag() == Some(context_constructed(0)) {
            return Err(Error::new(ErrorCode::Unsupported));
        }

        let mut sig_algo = signer.expect_sequence()?;
        sig_algo.expect_oid(OID_ECDSA_WITH_SHA256)?;

        let signature_der = signer.expect(TAG_OCTET_STRING)?.content;
        let mut raw = [0u8; 64];
        ecdsa_sig_value_to_raw(signature_der, &mut raw)?;

        // unsignedAttrs [1] IMPLICIT is optional and covered by nothing; its presence does
        // not affect the signature, so it is ignored.

        Ok(Self {
            content,
            signer_key_id,
            signature: Signature::from_bytes(raw),
        })
    }

    /// Verifies the signature against a CSA signing key.
    ///
    /// The caller supplies the key, because a CD names its signer only by key identifier and
    /// the set of trusted CSA keys is the commissioner's policy, not this crate's.
    pub fn verify(&self, csa_public_key: &PublicKey) -> Result<bool> {
        verify(csa_public_key, self.content, &self.signature)
    }

    /// Parses the `eContent` as certification elements.
    pub fn elements(&self) -> Result<CertificationElements<'a>> {
        CertificationElements::decode(self.content)
    }
}

/// A `SEQUENCE` tag, re-exported so a caller building a CMS fixture does not reach into
/// [`crate::der`].
pub const TAG_CMS_SEQUENCE: u8 = TAG_SEQUENCE;
