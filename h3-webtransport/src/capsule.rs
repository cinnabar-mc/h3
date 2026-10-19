//! Incremental WebTransport close capsules carried by the original CONNECT DATA owner.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::{
    error::{Code, StreamError},
    proto::{coding::Encode, varint::VarInt},
};

const CLOSE_SESSION: VarInt = VarInt::from_u32(0x2843);
const MAX_REASON_BYTES: usize = 1024;

/// The original peer's close code and bounded reason prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClose {
    /// The peer's original 32-bit session error code.
    pub code: u32,
    /// At most 1024 original reason bytes; unretained bytes are consumed before completion.
    pub reason: Bytes,
}

#[derive(Clone, Copy)]
enum Phase {
    Kind,
    Length(u64),
    Body { kind: u64, remaining: u64 },
}

/// Keeps only an incomplete varint and the bounded known close prefix, never unknown bodies.
pub(crate) struct Capsules {
    phase: Phase,
    integer: [u8; VarInt::MAX_SIZE],
    integer_len: usize,
    code: [u8; 4],
    code_len: usize,
    reason: BytesMut,
}

impl Default for Capsules {
    fn default() -> Self {
        Self {
            phase: Phase::Kind,
            integer: [0; VarInt::MAX_SIZE],
            integer_len: 0,
            code: [0; 4],
            code_len: 0,
            reason: BytesMut::new(),
        }
    }
}

impl Capsules {
    /// Consumes original DATA bytes across arbitrary boundaries without retaining their backing.
    pub(crate) fn receive(
        &mut self,
        input: &mut impl Buf,
    ) -> Result<Option<SessionClose>, StreamError> {
        loop {
            match self.phase {
                Phase::Kind => match self.read_integer(input)? {
                    Some(kind) => self.phase = Phase::Length(kind),
                    None => return Ok(None),
                },
                Phase::Length(kind) => match self.read_integer(input)? {
                    Some(length) => {
                        if kind == CLOSE_SESSION.into_inner() && length < self.code.len() as u64 {
                            return Err(malformed());
                        }
                        self.phase = Phase::Body {
                            kind,
                            remaining: length,
                        };
                    }
                    None => return Ok(None),
                },
                Phase::Body { kind, remaining } => {
                    if remaining == 0 {
                        self.phase = Phase::Kind;
                        if kind == CLOSE_SESSION.into_inner() {
                            return Ok(Some(SessionClose {
                                code: u32::from_be_bytes(self.code),
                                reason: self.reason.split().freeze(),
                            }));
                        }
                        continue;
                    }
                    if !input.has_remaining() {
                        return Ok(None);
                    }
                    let count = remaining.min(input.remaining() as u64) as usize;
                    let mut body = (&mut *input).take(count);
                    if kind == CLOSE_SESSION.into_inner() {
                        let code = (self.code.len() - self.code_len).min(body.remaining());
                        body.copy_to_slice(&mut self.code[self.code_len..self.code_len + code]);
                        self.code_len += code;
                        let reason = (MAX_REASON_BYTES - self.reason.len()).min(body.remaining());
                        self.reason.put(body.copy_to_bytes(reason));
                    }
                    body.advance(body.remaining());
                    self.phase = Phase::Body {
                        kind,
                        remaining: remaining - count as u64,
                    };
                }
            }
        }
    }

    /// Distinguishes complete inter-capsule EOF from a truncated header, code or declared body.
    pub(crate) fn finish(&self) -> Result<(), StreamError> {
        if matches!(self.phase, Phase::Kind) && self.integer_len == 0 {
            Ok(())
        } else {
            Err(malformed())
        }
    }

    /// Uses the existing maintained varint decoder once its finite original prefix is complete.
    fn read_integer(&mut self, input: &mut impl Buf) -> Result<Option<u64>, StreamError> {
        if self.integer_len == 0 {
            if !input.has_remaining() {
                return Ok(None);
            }
            self.integer[0] = input.get_u8();
            self.integer_len = 1;
        }
        let length = VarInt::encoded_size(self.integer[0]);
        let count = (length - self.integer_len).min(input.remaining());
        input.copy_to_slice(&mut self.integer[self.integer_len..self.integer_len + count]);
        self.integer_len += count;
        if self.integer_len < length {
            return Ok(None);
        }
        let value = VarInt::decode(&mut &self.integer[..length]).map_err(|_| malformed())?;
        self.integer_len = 0;
        Ok(Some(value.into_inner()))
    }
}

/// Encodes one bounded close body; HTTP3 DATA framing remains owned by RequestStream.
pub(crate) fn encode_close(code: u32, reason: &str) -> Bytes {
    let mut end = reason.len().min(MAX_REASON_BYTES);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    let mut body = BytesMut::with_capacity(2 * VarInt::MAX_SIZE + 4 + end);
    CLOSE_SESSION.encode(&mut body);
    VarInt::from_u32(4 + end as u32).encode(&mut body);
    body.put_u32(code);
    body.put_slice(&reason.as_bytes()[..end]);
    body.freeze()
}

/// Never includes peer-controlled capsule values or retained reason bytes in an error.
fn malformed() -> StreamError {
    StreamError::StreamError {
        code: Code::H3_DATAGRAM_ERROR,
        reason: "malformed WebTransport session capsule".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGINAL_CLOSE: &[u8] = &[0x68, 0x43, 0x05, 0, 0, 0, 42, b'x'];

    #[test]
    fn close_capsule_keeps_every_original_split_boundary() {
        for split in 0..=ORIGINAL_CLOSE.len() {
            let mut decoder = Capsules::default();
            let first = decoder.receive(&mut &ORIGINAL_CLOSE[..split]).unwrap();
            let closed = match first {
                Some(closed) => closed,
                None => decoder
                    .receive(&mut &ORIGINAL_CLOSE[split..])
                    .unwrap()
                    .unwrap(),
            };
            assert_eq!(closed.code, 42);
            assert_eq!(closed.reason, &b"x"[..]);
            decoder.finish().unwrap();
        }
    }

    #[test]
    fn close_capsule_skips_unknown_payload_before_the_original_close() {
        let mut prefix = BytesMut::new();
        VarInt::from_u32(0xdead).encode(&mut prefix);
        VarInt::from_u32(8192).encode(&mut prefix);
        let mut decoder = Capsules::default();
        assert!(decoder.receive(&mut prefix).unwrap().is_none());
        for _ in 0..128 {
            assert!(decoder.receive(&mut &[0xff; 64][..]).unwrap().is_none());
        }
        let closed = decoder.receive(&mut ORIGINAL_CLOSE).unwrap().unwrap();
        assert_eq!(closed.code, 42);
        assert_eq!(closed.reason, &b"x"[..]);
    }

    #[test]
    fn close_capsule_consumes_the_whole_body_but_keeps_only_original_reason_prefix() {
        let mut wire = BytesMut::new();
        CLOSE_SESSION.encode(&mut wire);
        VarInt::from_u32(4 + MAX_REASON_BYTES as u32 + 3).encode(&mut wire);
        wire.put_u32(7);
        wire.extend_from_slice(&[0xff; MAX_REASON_BYTES + 3]);
        let mut decoder = Capsules::default();
        let closed = decoder.receive(&mut wire).unwrap().unwrap();
        assert!(wire.is_empty());
        assert_eq!(closed.code, 7);
        assert_eq!(closed.reason, &[0xff; MAX_REASON_BYTES][..]);
        decoder.finish().unwrap();
    }

    #[test]
    fn close_capsule_truncated_header_or_declared_body_never_becomes_clean_eof() {
        Capsules::default().finish().unwrap();
        for wire in [
            &ORIGINAL_CLOSE[..1],
            &ORIGINAL_CLOSE[..2],
            &ORIGINAL_CLOSE[..3],
            &ORIGINAL_CLOSE[..7],
        ] {
            let mut decoder = Capsules::default();
            assert!(decoder.receive(&mut &wire[..]).unwrap().is_none());
            assert!(decoder.finish().is_err());
        }
        let mut decoder = Capsules::default();
        assert!(decoder.receive(&mut &[0x68, 0x43, 3][..]).is_err());
    }

    #[test]
    fn close_capsule_local_reason_truncation_keeps_utf8_boundary() {
        let reason = format!("{}\u{1f600}", "x".repeat(MAX_REASON_BYTES - 1));
        let mut wire = encode_close(5, &reason);
        let closed = Capsules::default().receive(&mut wire).unwrap().unwrap();
        assert_eq!(closed.code, 5);
        assert_eq!(closed.reason, "x".repeat(MAX_REASON_BYTES - 1));
        assert!(std::str::from_utf8(&closed.reason).is_ok());
    }
}
