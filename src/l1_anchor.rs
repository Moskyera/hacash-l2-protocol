//! Versioned provenance for one concrete Hacash L1 channel incarnation.
//!
//! The fullnode channel query does not expose a funding transaction hash or
//! an inclusion proof.  We therefore commit to the immutable opening fields
//! returned by that query and label the source honestly as a fullnode
//! observation, not as a trustless L1 proof.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::LocalChannel;

pub const L1_CHANNEL_ANCHOR_DOMAIN_V1: &[u8] = b"HACASH_L1_CHANNEL_ANCHOR_V1";
pub const L1_CHANNEL_ANCHOR_SCHEMA_V1: u16 = 1;
pub const HACASH_MAINNET_GENESIS_HASH_HEX: &str =
    "000000077790ba2fcdeaef4a4299d9b667135bac577ce204dee8388f1b97f7e6";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum L1AnchorSourceV1 {
    FullnodeStateQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct L1ChannelAnchorV1 {
    pub schema_version: u16,
    pub source: L1AnchorSourceV1,
    pub network_genesis_hash_hex: String,
    pub channel_id: String,
    /// Deterministic digest of the immutable opening fields below.
    pub funding_incarnation_hash_hex: String,
    pub reuse_version: u32,
    pub open_height: u64,
    pub arbitration_lock: u16,
    pub interest_attribution: u8,
    pub left_address: String,
    pub right_address: String,
    pub left_funded_hac_zhu: u64,
    pub right_funded_hac_zhu: u64,
    pub left_funded_satoshi: u64,
    pub right_funded_satoshi: u64,
    /// Fullnode tip observed immediately before the channel query.
    pub observed_height: u64,
    pub observed_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct L1ChannelObservationV1 {
    pub status: u8,
    pub close_height: u64,
    pub anchor: L1ChannelAnchorV1,
}

impl L1ChannelAnchorV1 {
    pub fn funded_hac_zhu(&self) -> Result<u64, String> {
        self.left_funded_hac_zhu
            .checked_add(self.right_funded_hac_zhu)
            .ok_or_else(|| "L1 channel anchor HAC total overflow".to_string())
    }

    pub fn funded_satoshi(&self) -> Result<u64, String> {
        self.left_funded_satoshi
            .checked_add(self.right_funded_satoshi)
            .ok_or_else(|| "L1 channel anchor satoshi total overflow".to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != L1_CHANNEL_ANCHOR_SCHEMA_V1 {
            return Err(format!(
                "unsupported L1 channel anchor schema {}; expected {}",
                self.schema_version, L1_CHANNEL_ANCHOR_SCHEMA_V1
            ));
        }
        decode_lower_hex(
            &self.network_genesis_hash_hex,
            32,
            "network_genesis_hash_hex",
        )?;
        if self.network_genesis_hash_hex != HACASH_MAINNET_GENESIS_HASH_HEX {
            return Err("L1 channel anchor is not bound to Hacash mainnet genesis".into());
        }
        decode_lower_hex(&self.channel_id, 16, "channel_id")?;
        decode_lower_hex(
            &self.funding_incarnation_hash_hex,
            32,
            "funding_incarnation_hash_hex",
        )?;
        if self.open_height == 0 {
            return Err("L1 channel anchor open_height must be greater than zero".into());
        }
        if self.observed_height < self.open_height {
            return Err("L1 channel anchor was observed below its open_height".into());
        }
        if self.observed_unix == 0 {
            return Err("L1 channel anchor observed_unix must be greater than zero".into());
        }
        if self.interest_attribution > 2 {
            return Err("L1 channel anchor interest_attribution must be 0, 1, or 2".into());
        }
        validate_address(&self.left_address, "left_address")?;
        validate_address(&self.right_address, "right_address")?;
        if self.left_address == self.right_address {
            return Err("L1 channel anchor parties must be distinct".into());
        }
        self.funded_hac_zhu()?;
        self.funded_satoshi()?;
        let expected = self.calculate_incarnation_hash_hex()?;
        if !constant_time_eq(
            expected.as_bytes(),
            self.funding_incarnation_hash_hex.as_bytes(),
        ) {
            return Err(
                "funding_incarnation_hash_hex does not match canonical L1 opening fields".into(),
            );
        }
        Ok(())
    }

    pub fn validate_against_channel(&self, channel: &LocalChannel) -> Result<(), String> {
        self.validate()?;
        if self.channel_id != channel.channel_id {
            return Err("L1 channel anchor id does not match registered channel".into());
        }
        if self.left_address != channel.left_address || self.right_address != channel.right_address
        {
            return Err("L1 channel parties do not match registered channel parties".into());
        }
        let registered_hac = crate::amounts::parse_zhu(&channel.left_hac)?
            .checked_add(crate::amounts::parse_zhu(&channel.right_hac)?)
            .ok_or("registered channel HAC total overflow")?;
        if self.funded_hac_zhu()? != registered_hac {
            return Err("L1 channel HAC funding total does not match registration".into());
        }
        let registered_satoshi = channel
            .left_satoshi
            .checked_add(channel.right_satoshi)
            .ok_or("registered channel satoshi total overflow")?;
        if self.funded_satoshi()? != registered_satoshi {
            return Err("L1 channel satoshi funding total does not match registration".into());
        }
        Ok(())
    }

    pub fn calculate_incarnation_hash_hex(&self) -> Result<String, String> {
        let mut out = Vec::with_capacity(256);
        append_bytes(&mut out, L1_CHANNEL_ANCHOR_DOMAIN_V1);
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        append_bytes(
            &mut out,
            &decode_lower_hex(
                &self.network_genesis_hash_hex,
                32,
                "network_genesis_hash_hex",
            )?,
        );
        append_bytes(
            &mut out,
            &decode_lower_hex(&self.channel_id, 16, "channel_id")?,
        );
        out.extend_from_slice(&self.reuse_version.to_be_bytes());
        out.extend_from_slice(&self.open_height.to_be_bytes());
        out.extend_from_slice(&self.arbitration_lock.to_be_bytes());
        out.push(self.interest_attribution);
        append_string(&mut out, &self.left_address)?;
        append_string(&mut out, &self.right_address)?;
        for value in [
            self.left_funded_hac_zhu,
            self.right_funded_hac_zhu,
            self.left_funded_satoshi,
            self.right_funded_satoshi,
        ] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        Ok(hex::encode(crate::hacash_keys::sha3(&out)))
    }
}

/// Parse the exact `/query/channel?...&unit=fin` response and bind it to the
/// requested channel id. Unknown top-level fields fail closed so a changed L1
/// schema cannot silently alter the commitment inputs.
pub fn parse_fullnode_channel_observation(
    requested_channel_id: &str,
    value: &Value,
    observed_height: u64,
    observed_unix: u64,
) -> Result<L1ChannelObservationV1, String> {
    let object = value
        .as_object()
        .ok_or("fullnode channel response must be a JSON object")?;
    const ALLOWED: &[&str] = &[
        "ret",
        "id",
        "status",
        "open_height",
        "err",
        "close_height",
        "reuse_version",
        "arbitration_lock",
        "interest_attribution",
        "left",
        "right",
        "challenging",
        "distribution",
        "final_arrival",
    ];
    if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(format!("unknown fullnode channel response field: {key}"));
    }
    let ret = required_u64(object, "ret")?;
    if ret != 0 {
        let detail = object
            .get("err")
            .and_then(Value::as_str)
            .unwrap_or("unknown fullnode error");
        return Err(format!("fullnode channel query failed: {detail}"));
    }

    let requested = normalize_channel_id(requested_channel_id)?;
    let response_id = required_string(object, "id")?;
    let response_id = normalize_channel_id(response_id)?;
    if response_id != requested {
        return Err("fullnode returned a different channel id".into());
    }
    let status = u8::try_from(required_u64(object, "status")?)
        .map_err(|_| "fullnode channel status exceeds u8")?;
    if status > 3 {
        return Err("fullnode channel status must be between 0 and 3".into());
    }
    let open_height = required_u64(object, "open_height")?;
    let close_height = required_u64(object, "close_height")?;
    let reuse_version = u32::try_from(required_u64(object, "reuse_version")?)
        .map_err(|_| "fullnode channel reuse_version exceeds u32")?;
    let arbitration_lock = u16::try_from(required_u64(object, "arbitration_lock")?)
        .map_err(|_| "fullnode channel arbitration_lock exceeds u16")?;
    let interest_attribution = u8::try_from(required_u64(object, "interest_attribution")?)
        .map_err(|_| "fullnode channel interest_attribution exceeds u8")?;
    let left = parse_party(object.get("left"), "left")?;
    let right = parse_party(object.get("right"), "right")?;

    let mut anchor = L1ChannelAnchorV1 {
        schema_version: L1_CHANNEL_ANCHOR_SCHEMA_V1,
        source: L1AnchorSourceV1::FullnodeStateQuery,
        network_genesis_hash_hex: HACASH_MAINNET_GENESIS_HASH_HEX.into(),
        channel_id: requested,
        funding_incarnation_hash_hex: String::new(),
        reuse_version,
        open_height,
        arbitration_lock,
        interest_attribution,
        left_address: left.address,
        right_address: right.address,
        left_funded_hac_zhu: left.hac_zhu,
        right_funded_hac_zhu: right.hac_zhu,
        left_funded_satoshi: left.satoshi,
        right_funded_satoshi: right.satoshi,
        observed_height,
        observed_unix,
    };
    anchor.funding_incarnation_hash_hex = anchor.calculate_incarnation_hash_hex()?;
    anchor.validate()?;
    Ok(L1ChannelObservationV1 {
        status,
        close_height,
        anchor,
    })
}

struct ParsedParty {
    address: String,
    hac_zhu: u64,
    satoshi: u64,
}

fn parse_party(value: Option<&Value>, field: &str) -> Result<ParsedParty, String> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| format!("fullnode channel {field} must be an object"))?;
    const ALLOWED: &[&str] = &["address", "hacash", "satoshi"];
    if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(format!("unknown fullnode channel {field} field: {key}"));
    }
    let address = required_string(object, "address")?.to_string();
    validate_address(&address, &format!("{field}.address"))?;
    let hacash = required_string(object, "hacash")?;
    let hac_zhu = crate::amounts::parse_zhu(hacash)
        .map_err(|error| format!("invalid fullnode {field}.hacash: {error}"))?;
    let satoshi = required_u64(object, "satoshi")?;
    Ok(ParsedParty {
        address,
        hac_zhu,
        satoshi,
    })
}

fn required_u64(object: &serde_json::Map<String, Value>, field: &str) -> Result<u64, String> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("fullnode channel field {field} must be an unsigned integer"))
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("fullnode channel field {field} must be a string"))
}

fn normalize_channel_id(value: &str) -> Result<String, String> {
    let id = value.trim().trim_start_matches("0x");
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("channel id must be exactly 16 bytes of hex".into());
    }
    Ok(id.to_ascii_lowercase())
}

fn validate_address(address: &str, field: &str) -> Result<(), String> {
    if address.is_empty() || address.len() > 128 || address.trim() != address {
        return Err(format!("{field} must be a trimmed 1..128 byte string"));
    }
    Ok(())
}

fn decode_lower_hex(value: &str, bytes: usize, field: &str) -> Result<Vec<u8>, String> {
    if value.len() != bytes * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{field} must be exactly {bytes} bytes of lowercase hex"
        ));
    }
    hex::decode(value).map_err(|error| format!("invalid {field}: {error}"))
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn append_string(output: &mut Vec<u8>, value: &str) -> Result<(), String> {
    if value.len() > u32::MAX as usize {
        return Err("canonical L1 anchor string exceeds u32 length".into());
    }
    append_bytes(output, value.as_bytes());
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> Value {
        serde_json::json!({
            "ret": 0,
            "id": "11".repeat(16),
            "status": 0,
            "open_height": 12345,
            "close_height": 0,
            "reuse_version": 2,
            "arbitration_lock": 5000,
            "interest_attribution": 0,
            "left": {
                "address": "1LeftAddress",
                "hacash": "6:245",
                "satoshi": 30
            },
            "right": {
                "address": "1RightAddress",
                "hacash": "4:245",
                "satoshi": 70
            }
        })
    }

    #[test]
    fn parses_exact_financial_amounts_and_builds_stable_anchor() {
        let observation =
            parse_fullnode_channel_observation(&"11".repeat(16), &response(), 13000, 77).unwrap();
        assert_eq!(observation.status, 0);
        assert_eq!(observation.anchor.left_funded_hac_zhu, 600_000);
        assert_eq!(observation.anchor.right_funded_hac_zhu, 400_000);
        assert_eq!(
            observation.anchor.funding_incarnation_hash_hex,
            observation.anchor.calculate_incarnation_hash_hex().unwrap()
        );
    }

    #[test]
    fn rejects_wrong_id_error_response_unknown_fields_and_float_amounts() {
        assert!(
            parse_fullnode_channel_observation(&"22".repeat(16), &response(), 13000, 77).is_err()
        );

        let mut error = response();
        error["ret"] = serde_json::json!(1);
        assert!(parse_fullnode_channel_observation(&"11".repeat(16), &error, 13000, 77).is_err());

        let mut unknown = response();
        unknown["funding_tx_hash"] = serde_json::json!("aa".repeat(32));
        assert!(parse_fullnode_channel_observation(&"11".repeat(16), &unknown, 13000, 77).is_err());

        let mut float = response();
        float["left"]["hacash"] = serde_json::json!("0.006");
        assert!(parse_fullnode_channel_observation(&"11".repeat(16), &float, 13000, 77).is_err());
    }

    #[test]
    fn anchor_hash_changes_for_a_reused_channel_incarnation() {
        let first =
            parse_fullnode_channel_observation(&"11".repeat(16), &response(), 13000, 77).unwrap();
        let mut reused = response();
        reused["reuse_version"] = serde_json::json!(3);
        reused["open_height"] = serde_json::json!(14000);
        let second =
            parse_fullnode_channel_observation(&"11".repeat(16), &reused, 14500, 88).unwrap();
        assert_ne!(
            first.anchor.funding_incarnation_hash_hex,
            second.anchor.funding_incarnation_hash_hex
        );
    }
}
