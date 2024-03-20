/*
    GraCe a FOSS implementation of the AWDL protocol.
    Copyright (C) 2024  Frostie314159

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use std::time::Duration;

use ieee80211::common::TU;
use mac_parser::MACAddress;

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
pub const DEFAULT_CHANNEL_SEQUENCE_TOTAL_DURATION: Duration =
    mul_duration!(DEFAULT_SLOT_DURATION, DEFAULT_CHANNEL_SEQUENCE_SLOT_COUNT);
pub const AWDL_BSSID: MACAddress = MACAddress::new([0x00, 0x25, 0x00, 0xff, 0x94, 0x73]);
pub const UNICAST_GUARD_INTERVAL_IN_TU: usize = 3;
pub const UNICAST_GUARD_INTERVAL: Duration = mul_duration!(TU, UNICAST_GUARD_INTERVAL_IN_TU);
