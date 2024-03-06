use std::time::Duration;

use ieee80211::common::TU;

macro_rules! mul_duration {
    ($duration:expr, $multiplier:expr) => {
        Duration::from_micros($duration.as_micros() as u64 * $multiplier as u64)
    };
}

pub const AW_DURATION: Duration = mul_duration!(TU, 16);
pub const DEFAULT_EAW_COUNT: usize = 3;
pub const DEFAULT_SLOT_AW_COUNT: usize = DEFAULT_EAW_COUNT + 1;
pub const DEFAULT_SLOT_DURATION: Duration = mul_duration!(AW_DURATION, DEFAULT_SLOT_AW_COUNT);
pub const DEFAULT_CHANNEL_SEQUENCE_SLOT_COUNT: usize = 16;
pub const DEFAULT_CHANNEL_SEQUENCE_AW_COUNT: usize =
    DEFAULT_SLOT_AW_COUNT * DEFAULT_CHANNEL_SEQUENCE_SLOT_COUNT;
pub const DEFAULT_CHANNEL_SEQUENCE_TOTAL_DURATION: Duration =
    mul_duration!(DEFAULT_SLOT_DURATION, DEFAULT_CHANNEL_SEQUENCE_SLOT_COUNT);
