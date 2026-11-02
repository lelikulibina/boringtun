// Copyright (c) 2026 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! AmneziaWG I1-I5 pre-handshake signature packet templates.
//!
//! The reference implementation sends each configured chain as a standalone
//! UDP datagram, in I1..I5 order, before Jc junk and the Noise initiation.
//! The data and data-string transforms therefore receive an empty source slice
//! here, matching the reference call site that passes nil.

use rand_core::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SIGNATURE_PACKET_SIZE: usize = 65_507;
const CHARS52: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS10: &[u8] = b"0123456789";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignaturePacket {
    spec: String,
    transforms: Vec<Transform>,
    encoded_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Transform {
    Bytes(Vec<u8>),
    Timestamp,
    Random(usize),
    RandomChars(usize),
    RandomDigits(usize),
    Data,
    DataString,
    DataSize(usize),
}

impl SignaturePacket {
    /// Parse the angle-bracket transform syntax used by amneziawg-go.
    /// Unknown tags, malformed delimiters and invalid lengths are rejected.
    /// Lengths are bounded by the maximum IPv4 UDP payload to prevent a
    /// configuration from causing unbounded allocations or send-time panics.
    pub(crate) fn parse(spec: &str) -> Result<Option<Self>, String> {
        let mut transforms = Vec::new();
        let mut errors = Vec::new();
        let mut remaining = spec;

        while let Some(start) = remaining.find('<') {
            let after_start = &remaining[start + 1..];
            let Some(end) = after_start.find('>') else {
                return Err("missing enclosing >".to_owned());
            };
            let tag = &after_start[..end];
            remaining = &after_start[end + 1..];

            let mut parts = tag.split_whitespace();
            let Some(name) = parts.next() else {
                errors.push("empty tag".to_owned());
                continue;
            };
            let value = parts.next().unwrap_or("");

            let parsed = match name {
                "b" => {
                    let value = value.strip_prefix("0x").unwrap_or(value);
                    if value.is_empty() {
                        Err("empty argument".to_owned())
                    } else if value.len() % 2 != 0 {
                        Err("odd amount of hex symbols".to_owned())
                    } else if value.len() / 2 > MAX_SIGNATURE_PACKET_SIZE {
                        Err(format!(
                            "byte prefix exceeds {MAX_SIGNATURE_PACKET_SIZE} bytes"
                        ))
                    } else {
                        hex::decode(value)
                            .map(Transform::Bytes)
                            .map_err(|e| e.to_string())
                    }
                }
                "t" => Ok(Transform::Timestamp),
                "r" | "rc" | "rd" | "dz" => {
                    let length = value
                        .parse::<usize>()
                        .map_err(|e| format!("invalid <{name}> length: {e}"))?;
                    if length > MAX_SIGNATURE_PACKET_SIZE {
                        Err(format!("<{name}> length exceeds {MAX_SIGNATURE_PACKET_SIZE}"))
                    } else {
                        Ok(match name {
                            "r" => Transform::Random(length),
                            "rc" => Transform::RandomChars(length),
                            "rd" => Transform::RandomDigits(length),
                            _ => Transform::DataSize(length),
                        })
                    }
                }
                "d" => Ok(Transform::Data),
                "ds" => Ok(Transform::DataString),
                _ => Err(format!("unknown tag <{name}>")),
            };

            match parsed {
                Ok(transform) => transforms.push(transform),
                Err(error) => errors.push(format!("failed to build <{name}>: {error}")),
            }
        }

        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        if transforms.is_empty() {
            return Ok(None);
        }

        let mut encoded_len = 0usize;
        for transform in &transforms {
            let length = match transform {
                Transform::Bytes(bytes) => bytes.len(),
                Transform::Timestamp => 4,
                Transform::Random(n)
                | Transform::RandomChars(n)
                | Transform::RandomDigits(n)
                | Transform::DataSize(n) => *n,
                Transform::Data | Transform::DataString => 0,
            };
            encoded_len = encoded_len
                .checked_add(length)
                .ok_or_else(|| "signature packet length overflow".to_owned())?;
            if encoded_len > MAX_SIGNATURE_PACKET_SIZE {
                return Err(format!(
                    "signature packet exceeds {MAX_SIGNATURE_PACKET_SIZE} bytes"
                ));
            }
        }

        Ok(Some(Self {
            spec: spec.to_owned(),
            transforms,
            encoded_len,
        }))
    }

    pub(crate) fn spec(&self) -> &str {
        &self.spec
    }

    pub(crate) fn encode(&self, rng: &mut impl RngCore) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.encoded_len);
        for transform in &self.transforms {
            match transform {
                Transform::Bytes(bytes) => output.extend_from_slice(bytes),
                Transform::Timestamp => {
                    let seconds = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    output.extend_from_slice(&seconds.to_be_bytes());
                }
                Transform::Random(length) => {
                    let start = output.len();
                    output.resize(start + *length, 0);
                    rng.fill_bytes(&mut output[start..]);
                }
                Transform::RandomChars(length) => {
                    let start = output.len();
                    output.resize(start + *length, 0);
                    rng.fill_bytes(&mut output[start..]);
                    for byte in &mut output[start..] {
                        *byte = CHARS52[(*byte as usize) % CHARS52.len()];
                    }
                }
                Transform::RandomDigits(length) => {
                    let start = output.len();
                    output.resize(start + length, 0);
                    rng.fill_bytes(&mut output[start..]);
                    for byte in &mut output[start..] {
                        *byte = DIGITS10[(*byte as usize) % DIGITS10.len()];
                    }
                }
                // I1-I5 are sent with a nil source slice in the reference
                // implementation, so both data transforms encode zero bytes.
                Transform::Data | Transform::DataString => {}
                Transform::DataSize(length) => {
                    // Big-endian source length, matching the reference. The
                    // source is empty for standalone pre-handshake packets.
                    let start = output.len();
                    output.resize(start + length, 0);
                }
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn parses_all_reference_transform_tags() {
        for spec in [
            "<b 0xdeadbeef>",
            "<t>",
            "<r 16>",
            "<rc 12>",
            "<rd 8>",
            "<d>",
            "<ds>",
            "<dz 2>",
        ] {
            assert!(SignaturePacket::parse(spec).unwrap().is_some(), "{spec}");
        }
    }

    #[test]
    fn emits_reference_prefixes_in_chain_order() {
        let packet = SignaturePacket::parse("<b deadbeef><dz 2><d>").unwrap().unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        assert_eq!(packet.encode(&mut rng), vec![0xde, 0xad, 0xbe, 0xef, 0, 0]);
    }

    #[test]
    fn random_character_and_digit_transforms_use_reference_alphabets() {
        let packet = SignaturePacket::parse("<rc 64><rd 64>").unwrap().unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let encoded = packet.encode(&mut rng);
        assert_eq!(encoded.len(), 128);
        assert!(encoded[..64].iter().all(|b| CHARS52.contains(b)));
        assert!(encoded[64..].iter().all(|b| DIGITS10.contains(b)));
    }

    #[test]
    fn rejects_malformed_or_unbounded_templates() {
        assert!(SignaturePacket::parse("<b abc>").is_err());
        assert!(SignaturePacket::parse("<r -1>").is_err());
        assert!(SignaturePacket::parse("<r 65508>").is_err());
        assert!(SignaturePacket::parse("<unknown 1>").is_err());
        assert!(SignaturePacket::parse("<r 4").is_err());
    }

    #[test]
    fn a_template_without_transforms_is_a_clear_operation() {
        assert!(SignaturePacket::parse("").unwrap().is_none());
        assert!(SignaturePacket::parse("plain text").unwrap().is_none());
    }
}
