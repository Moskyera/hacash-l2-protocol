//! Exact dual-currency helpers: HAC financial notation + satoshi.
//!
//! HAC financial notation is `mantissa:unit`: Mei is unit 248 and Zhu is
//! unit 240 (10^-8 HAC). The L2 ledger uses Zhu internally so every accepted
//! value is exact and arithmetic can be checked with `u64`.

use serde::{Deserialize, Serialize};

pub const UNIT_MEI: u8 = 248;
pub const UNIT_ZHU: u8 = 240;
pub const ZHU_PER_MEI: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HacAmount(u64);

impl HacAmount {
    pub fn parse(input: &str) -> Result<Self, String> {
        let value = input.trim();
        if value.is_empty() || value == "0" || value == "0:0" {
            return Ok(Self(0));
        }

        let (mantissa_raw, unit_raw) = value
            .split_once(':')
            .ok_or_else(|| "HAC amount must use financial notation mantissa:unit".to_string())?;
        if mantissa_raw.is_empty()
            || !mantissa_raw.bytes().all(|b| b.is_ascii_digit())
            || unit_raw.is_empty()
            || !unit_raw.bytes().all(|b| b.is_ascii_digit())
        {
            return Err("HAC amount must contain unsigned decimal digits only".into());
        }
        let mut mantissa = mantissa_raw
            .parse::<u64>()
            .map_err(|_| "HAC mantissa exceeds u64".to_string())?;
        let mut unit = unit_raw
            .parse::<u8>()
            .map_err(|_| "HAC unit must be between 0 and 255".to_string())?;
        if mantissa == 0 {
            return Ok(Self(0));
        }

        // Canonical HAC values remove trailing mantissa zeroes by increasing
        // the unit. This also recognizes exact Zhu values such as `10:239`.
        while mantissa % 10 == 0 && unit < u8::MAX {
            mantissa /= 10;
            unit += 1;
        }
        if unit < UNIT_ZHU {
            return Err("HAC precision below one Zhu (10^-8 HAC) is not supported".into());
        }
        let scale = 10u64
            .checked_pow((unit - UNIT_ZHU) as u32)
            .ok_or_else(|| "HAC amount exceeds the L2 u64 Zhu range".to_string())?;
        let zhu = mantissa
            .checked_mul(scale)
            .ok_or_else(|| "HAC amount exceeds the L2 u64 Zhu range".to_string())?;
        Ok(Self(zhu))
    }

    pub fn from_zhu(zhu: u64) -> Self {
        Self(zhu)
    }

    pub fn zhu(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self, String> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or_else(|| "HAC amount overflow".to_string())
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, String> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or_else(|| "insufficient HAC balance".to_string())
    }

    pub fn to_fin_string(self) -> String {
        format_zhu(self.0)
    }
}

pub fn parse_zhu(amount_hac: &str) -> Result<u64, String> {
    HacAmount::parse(amount_hac).map(HacAmount::zhu)
}

/// Transitional alias for fields that still carry the historical `_mei` name.
/// The returned value is exact Zhu; new code should call `parse_zhu`.
#[deprecated(note = "use parse_zhu; this compatibility alias returns exact Zhu")]
pub fn parse_mei(amount_hac: &str) -> Result<u64, String> {
    parse_zhu(amount_hac)
}

pub fn normalize_hac(amount_hac: &str) -> Result<String, String> {
    HacAmount::parse(amount_hac).map(HacAmount::to_fin_string)
}

pub fn format_zhu(mut zhu: u64) -> String {
    if zhu == 0 {
        return "0".into();
    }
    let mut unit = UNIT_ZHU;
    while zhu % 10 == 0 && unit < u8::MAX {
        zhu /= 10;
        unit += 1;
    }
    format!("{zhu}:{unit}")
}

/// Normalized amount for agent APIs (satoshi-first friendly).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DualAmount {
    /// Exact HAC amount in Zhu. This is the authoritative integer field.
    #[serde(default)]
    pub hac_zhu: u64,
    /// Whole Mei (whole HAC), retained as a compatibility/display field.
    #[serde(default)]
    pub hac_mei: u64,
    /// Canonical HAC financial-notation string; empty for satoshi-only.
    #[serde(default)]
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
}

impl DualAmount {
    pub fn try_from_parts(amount_hac: &str, amount_satoshi: u64) -> Result<Self, String> {
        let raw = amount_hac.trim();
        let hac_zhu = if raw.is_empty() { 0 } else { parse_zhu(raw)? };
        let amount_hac = if raw.is_empty() || hac_zhu == 0 {
            String::new()
        } else {
            format_zhu(hac_zhu)
        };
        Ok(Self {
            hac_zhu,
            hac_mei: hac_zhu / ZHU_PER_MEI,
            amount_hac,
            amount_satoshi,
        })
    }

    pub fn is_zero(&self) -> bool {
        self.hac_zhu == 0 && self.amount_satoshi == 0
    }

    pub fn display(&self) -> String {
        let mut parts = Vec::new();
        if !self.amount_hac.is_empty() {
            parts.push(format!("{} HAC", self.amount_hac));
        }
        if self.amount_satoshi > 0 {
            parts.push(format!("{} sat", self.amount_satoshi));
        }
        if parts.is_empty() {
            "0".into()
        } else {
            parts.join(" + ")
        }
    }

    pub fn for_payment(&self) -> (String, u64) {
        (self.amount_hac.clone(), self.amount_satoshi)
    }
}

/// Request body fragment: accepts exact `amount_hac`, satoshi, or whole Mei.
#[derive(Debug, Deserialize, Default)]
pub struct AmountInput {
    #[serde(default)]
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    /// Compatibility alias: whole Mei (1 Mei = 1 HAC).
    #[serde(default)]
    pub amount_mei: u64,
    #[serde(default)]
    pub satoshi: u64,
    /// Compatibility alias: whole Mei (1 Mei = 1 HAC).
    #[serde(default)]
    pub mei: u64,
}

impl AmountInput {
    pub fn resolve(&self) -> Result<DualAmount, String> {
        let sats = if self.amount_satoshi > 0 {
            self.amount_satoshi
        } else {
            self.satoshi
        };
        let mei = if self.amount_mei > 0 {
            self.amount_mei
        } else {
            self.mei
        };
        let hac = if self.amount_hac.trim().is_empty() && mei > 0 {
            format!("{mei}:{UNIT_MEI}")
        } else {
            self.amount_hac.clone()
        };
        DualAmount::try_from_parts(&hac, sats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_official_hac_units_exactly() {
        assert_eq!(parse_zhu("1:248").unwrap(), 100_000_000);
        assert_eq!(parse_zhu("1:247").unwrap(), 10_000_000);
        assert_eq!(parse_zhu("12:248").unwrap(), 1_200_000_000);
        assert_eq!(parse_zhu("1456:245").unwrap(), 145_600_000);
        assert_eq!(parse_zhu("10:239").unwrap(), 1);
    }

    #[test]
    fn rejects_sub_zhu_invalid_and_overflow_values() {
        assert!(parse_zhu("1:239").is_err());
        assert!(parse_zhu("-1:248").is_err());
        assert!(parse_zhu("1.5:248").is_err());
        assert!(parse_zhu("1:256").is_err());
        assert!(parse_zhu("18446744073709551615:241").is_err());
    }

    #[test]
    fn canonical_round_trip_and_mei_alias() {
        assert_eq!(normalize_hac("10000000:240").unwrap(), "1:247");
        assert_eq!(parse_zhu(&format_zhu(u64::MAX)).unwrap(), u64::MAX);
        let amount = AmountInput {
            amount_mei: 2,
            ..Default::default()
        }
        .resolve()
        .unwrap();
        assert_eq!(amount.hac_zhu, 200_000_000);
        assert_eq!(amount.hac_mei, 2);
        assert_eq!(amount.amount_hac, "2:248");
    }
}
