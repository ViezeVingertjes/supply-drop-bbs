#![allow(missing_docs)]

use meshcore_kiss::hw::frame::RadioParams;
use meshcore_kiss::radio::{validate_radio_params, RadioParamError};

fn sane() -> RadioParams {
    RadioParams {
        frequency_hz: 869_618_000,
        bandwidth_hz: 62_500,
        spreading_factor: 7,
        coding_rate: 5,
    }
}

#[test]
fn a_sane_configuration_is_accepted() {
    assert!(validate_radio_params(&sane()).is_ok());
}

#[test]
fn a_frequency_entered_in_megahertz_is_rejected() {
    let params = RadioParams {
        frequency_hz: 869,
        ..sane()
    };
    assert_eq!(
        validate_radio_params(&params),
        Err(RadioParamError::FrequencyOutOfRange { frequency_hz: 869 })
    );
}

#[test]
fn a_zero_frequency_is_rejected() {
    let params = RadioParams {
        frequency_hz: 0,
        ..sane()
    };
    assert!(matches!(
        validate_radio_params(&params),
        Err(RadioParamError::FrequencyOutOfRange { .. })
    ));
}

#[test]
fn frequencies_outside_the_sx126x_range_are_rejected() {
    for frequency_hz in [136_999_999, 1_020_000_001, 2_400_000_000] {
        let params = RadioParams {
            frequency_hz,
            ..sane()
        };
        assert!(
            validate_radio_params(&params).is_err(),
            "{frequency_hz} Hz should be rejected"
        );
    }
}

#[test]
fn frequencies_at_the_range_edges_are_accepted() {
    for frequency_hz in [137_000_000, 1_020_000_000] {
        let params = RadioParams {
            frequency_hz,
            ..sane()
        };
        assert!(
            validate_radio_params(&params).is_ok(),
            "{frequency_hz} Hz should be accepted"
        );
    }
}

#[test]
fn an_implausible_bandwidth_is_rejected() {
    for bandwidth_hz in [0, 1_000, 1_000_000] {
        let params = RadioParams {
            bandwidth_hz,
            ..sane()
        };
        assert!(
            validate_radio_params(&params).is_err(),
            "{bandwidth_hz} Hz bandwidth should be rejected"
        );
    }
}

#[test]
fn a_spreading_factor_outside_five_to_twelve_is_rejected() {
    for spreading_factor in [0, 4, 13, 255] {
        let params = RadioParams {
            spreading_factor,
            ..sane()
        };
        assert_eq!(
            validate_radio_params(&params),
            Err(RadioParamError::SpreadingFactorOutOfRange { spreading_factor })
        );
    }
}

#[test]
fn a_coding_rate_outside_five_to_eight_is_rejected() {
    for coding_rate in [0, 4, 9] {
        let params = RadioParams {
            coding_rate,
            ..sane()
        };
        assert_eq!(
            validate_radio_params(&params),
            Err(RadioParamError::CodingRateOutOfRange { coding_rate })
        );
    }
}
