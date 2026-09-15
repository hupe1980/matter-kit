//! A bounds-checked little-endian cursor.
//!
//! Small enough to be obvious, which is the point. `clippy::indexing_slicing` and
//! `clippy::arithmetic_side_effects` are denied crate-wide, so every octet a wire format
//! reads or writes goes through here and "did that one forget to check the length?" has a
//! single answer.
//!
//! Matter is little-endian everywhere on the wire — message headers (§4.4), BTP frames
//! (§4.19.2), BLE service data (§5.4.2.5.6) — so the byte order is baked in rather than
//! offered as a choice that could be got wrong.

use crate::error::{Error, ErrorCode, Result, bail};

/// A cursor over a buffer, reading or writing but never both.
pub(crate) struct Cursor<'a> {
    write: Option<&'a mut [u8]>,
    read: &'a [u8],
    pos: usize,
    /// What running off the end is called. A truncated message header and a truncated BTP
    /// frame are different failures to the caller even though they are the same mistake here.
    truncated: ErrorCode,
}

impl<'a> Cursor<'a> {
    /// A cursor that writes into `out`. Overrunning it is always
    /// [`ErrorCode::BufferTooSmall`]: a buffer this crate was handed being too short is the
    /// caller's problem, never the wire's.
    pub(crate) fn writer(out: &'a mut [u8]) -> Self {
        Self {
            write: Some(out),
            read: &[],
            pos: 0,
            truncated: ErrorCode::BufferTooSmall,
        }
    }

    /// A cursor that reads from `buf`, reporting `truncated` when it runs out.
    pub(crate) fn reader(buf: &'a [u8], truncated: ErrorCode) -> Self {
        Self {
            write: None,
            read: buf,
            pos: 0,
            truncated,
        }
    }

    /// How many octets have been consumed or produced.
    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    /// Everything not yet read.
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.read.get(self.pos..).unwrap_or(&[])
    }

    fn advance(&mut self, n: usize) -> Result<usize> {
        let start = self.pos;
        self.pos = self.pos.checked_add(n).ok_or(Error::new(self.truncated))?;
        Ok(start)
    }

    /// Steps over `n` octets without reading them.
    pub(crate) fn skip(&mut self, n: usize) -> Result<()> {
        let start = self.advance(n)?;
        if self.read.get(start..self.pos).is_none() {
            return Err(Error::new(self.truncated));
        }
        Ok(())
    }

    /// Writes raw octets.
    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let start = self.advance(bytes.len())?;
        let Some(buf) = self.write.as_mut() else {
            bail!(InvalidState)
        };
        let Some(dst) = buf.get_mut(start..self.pos) else {
            bail!(BufferTooSmall)
        };
        dst.copy_from_slice(bytes);
        Ok(())
    }

    /// Reads `n` octets.
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let start = self.advance(n)?;
        self.read
            .get(start..self.pos)
            .ok_or(Error::new(self.truncated))
    }

    pub(crate) fn u8(&mut self, v: u8) -> Result<()> {
        self.put(&[v])
    }
    pub(crate) fn u16(&mut self, v: u16) -> Result<()> {
        self.put(&v.to_le_bytes())
    }
    pub(crate) fn u32(&mut self, v: u32) -> Result<()> {
        self.put(&v.to_le_bytes())
    }
    pub(crate) fn u64(&mut self, v: u64) -> Result<()> {
        self.put(&v.to_le_bytes())
    }
}

/// The reading half. Separate names so a misuse is a compile error, not a silent zero.
impl Cursor<'_> {
    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        let b = self.take(1)?;
        b.first().copied().ok_or(Error::new(self.truncated))
    }
    pub(crate) fn read_u16(&mut self) -> Result<u16> {
        let arr: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| Error::new(self.truncated))?;
        Ok(u16::from_le_bytes(arr))
    }
    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        let arr: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| Error::new(self.truncated))?;
        Ok(u32::from_le_bytes(arr))
    }
    pub(crate) fn read_u64(&mut self) -> Result<u64> {
        let arr: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| Error::new(self.truncated))?;
        Ok(u64::from_le_bytes(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_that_runs_off_the_end_is_refused_rather_than_truncated() {
        let mut buf = [0u8; 3];
        let mut w = Cursor::writer(&mut buf);
        w.u16(0xBEEF).expect("fits");
        assert_eq!(
            w.u16(0).map_err(|e| e.code()),
            Err(ErrorCode::BufferTooSmall)
        );
        assert_eq!(w.position(), 4, "the position still advanced past the end");
    }

    #[test]
    fn a_read_reports_the_caller_s_own_error_code() {
        // The same mistake is a truncated message header in one place and a malformed BTP
        // frame in another, and the caller above needs to tell them apart.
        let mut r = Cursor::reader(&[1, 2], ErrorCode::BtpMalformed);
        assert_eq!(r.read_u16().expect("fits"), 0x0201, "little-endian");
        assert_eq!(
            r.read_u8().map_err(|e| e.code()),
            Err(ErrorCode::BtpMalformed)
        );

        let mut r = Cursor::reader(&[1], ErrorCode::MessageTruncated);
        assert_eq!(
            r.read_u32().map_err(|e| e.code()),
            Err(ErrorCode::MessageTruncated)
        );
    }

    #[test]
    fn rest_is_everything_not_yet_read() {
        let mut r = Cursor::reader(&[1, 2, 3, 4], ErrorCode::MessageTruncated);
        r.skip(1).expect("skip");
        assert_eq!(r.rest(), &[2, 3, 4]);
        assert_eq!(r.take(3).expect("take"), &[2, 3, 4]);
        assert!(r.rest().is_empty());
    }
}
