//! Sanity checks on radio parameters before they reach the device.
//!
//! Writing radio parameters re-initialises the transceiver, and an impossible
//! value leaves the node deaf and silent until someone notices and corrects it
//! by hand. A frequency typed in megahertz rather than hertz is the common
//! way to get there: `869.618` becomes `869`, which the radio accepts as a
//! literal 869 Hz and stops working.
//!
//! The ranges here are the SX126x tuning range and the LoRa parameter ranges
//! MeshCore itself uses, so a value that fails these checks could not have
//! worked on any supported board.

use crate::hw::frame::RadioParams;

/// Lowest frequency the SX126x family tunes to.
pub const MIN_FREQUENCY_HZ: u32 = 137_000_000;

/// Highest frequency the SX126x family tunes to.
pub const MAX_FREQUENCY_HZ: u32 = 1_020_000_000;

/// Narrowest LoRa bandwidth the radio supports.
pub const MIN_BANDWIDTH_HZ: u32 = 7_800;

/// Widest LoRa bandwidth the radio supports.
pub const MAX_BANDWIDTH_HZ: u32 = 500_000;

/// A radio parameter that could not work on any supported board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RadioParamError {
    /// The carrier frequency lies outside the transceiver's tuning range.
    #[error(
        "frequency {frequency_hz} Hz is outside {MIN_FREQUENCY_HZ}-{MAX_FREQUENCY_HZ} Hz; \
         the value is in hertz, so 869.618 MHz is 869618000"
    )]
    FrequencyOutOfRange {
        /// The offending frequency.
        frequency_hz: u32,
    },

    /// The bandwidth lies outside the supported range.
    #[error("bandwidth {bandwidth_hz} Hz is outside {MIN_BANDWIDTH_HZ}-{MAX_BANDWIDTH_HZ} Hz")]
    BandwidthOutOfRange {
        /// The offending bandwidth.
        bandwidth_hz: u32,
    },

    /// The spreading factor lies outside 5 to 12.
    #[error("spreading factor {spreading_factor} is outside 5-12")]
    SpreadingFactorOutOfRange {
        /// The offending spreading factor.
        spreading_factor: u8,
    },

    /// The coding rate denominator lies outside 5 to 8.
    #[error("coding rate {coding_rate} is outside 5-8")]
    CodingRateOutOfRange {
        /// The offending coding rate.
        coding_rate: u8,
    },
}

/// Check radio parameters before writing them to the device.
///
/// # Errors
///
/// Returns the first parameter that could not work on a supported board.
pub fn validate_radio_params(params: &RadioParams) -> Result<(), RadioParamError> {
    if !(MIN_FREQUENCY_HZ..=MAX_FREQUENCY_HZ).contains(&params.frequency_hz) {
        return Err(RadioParamError::FrequencyOutOfRange {
            frequency_hz: params.frequency_hz,
        });
    }
    if !(MIN_BANDWIDTH_HZ..=MAX_BANDWIDTH_HZ).contains(&params.bandwidth_hz) {
        return Err(RadioParamError::BandwidthOutOfRange {
            bandwidth_hz: params.bandwidth_hz,
        });
    }
    if !(5..=12).contains(&params.spreading_factor) {
        return Err(RadioParamError::SpreadingFactorOutOfRange {
            spreading_factor: params.spreading_factor,
        });
    }
    if !(5..=8).contains(&params.coding_rate) {
        return Err(RadioParamError::CodingRateOutOfRange {
            coding_rate: params.coding_rate,
        });
    }
    Ok(())
}
