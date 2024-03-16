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

use std::{num::NonZeroU8, time::Duration};

use awdl_frame_parser::tlvs::sync_elect::{
    channel::{Band, Channel, ChannelBandwidth, LegacyFlags, SupportChannel},
    channel_sequence::ChannelSequence,
    ChannelSequenceTLV, SynchronizationParametersTLV,
};
use ieee80211::common::TU;
use tokio::time::{sleep, Instant};

use crate::{
    constants::{
        AW_DURATION, DEFAULT_CHANNEL_SEQUENCE_TOTAL_DURATION, DEFAULT_SLOT_AW_COUNT,
        DEFAULT_SLOT_DURATION, DEFAULT_SLOT_DURATION_IN_TU, UNICAST_GUARD_INTERVAL,
        UNICAST_GUARD_INTERVAL_IN_TU,
    },
    duration_rem,
};

const CHANNEL_44_FLAGS: (LegacyFlags, u8) = (
    LegacyFlags {
        band: Band::FiveGHz,
        channel_bandwidth: ChannelBandwidth::EightyMHz,
        support_channel: SupportChannel::Lower,
    },
    46,
);
const CHANNEL_6_FLAGS: (LegacyFlags, u8) = (
    LegacyFlags {
        band: Band::TwoPointFourGHz,
        channel_bandwidth: ChannelBandwidth::TwentyMHz,
        support_channel: SupportChannel::Primary,
    },
    6,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SyncState {
    pub channel_sequence: [(LegacyFlags, u8); 16],
    pub tsf_zero: Instant,
}
impl SyncState {
    pub fn new_with_default_chanseq() -> Self {
        Self {
            channel_sequence: { [CHANNEL_6_FLAGS; 16] },
            tsf_zero: Instant::now(),
        }
    }
    /// The Δt should be the sum Δt specified in the AF-Header and the time which has elapsed since the reception of that frame.
    pub fn new_with_sync_params_tlv_and_tx_delta(
        sync_params_tlv: SynchronizationParametersTLV,
        tx_delta: Duration,
    ) -> Option<Self> {
        let aw_period = sync_params_tlv.aw_period as i32;

        let elapsed_since_aw_begin_in_tu =
            aw_period.wrapping_sub(sync_params_tlv.remaining_aw_length as i32);
        let elapsed_since_slot_zero_in_tu =
            elapsed_since_aw_begin_in_tu + aw_period * sync_params_tlv.aw_seq_number as i32;
        let tsf = TU * elapsed_since_slot_zero_in_tu as u32 - tx_delta - TU;
        let ChannelSequence::Legacy(channel_sequence) =
            sync_params_tlv.channel_sequence.channel_sequence
        else {
            return None;
        };
        Some(Self {
            channel_sequence,
            tsf_zero: Instant::now() - tsf,
        })
    }
    pub fn distance_to_slot(&self, slot: usize, slot_offset: usize) -> usize {
        let next_slot = self.current_slot_in_chanseq() + slot_offset;
        if next_slot < slot {
            slot - next_slot
        } else {
            16 - slot + next_slot
        }
    }
    pub fn sync_to(&mut self, other_state: SyncState) {
        // This is the advantage of our approach.
        self.tsf_zero = other_state.tsf_zero;
    }
    pub fn elapsed_since_current_slot_zero(&self) -> Duration {
        // If this doesn't work, change it back to div.
        duration_rem!(
            self.tsf_zero.elapsed(),
            DEFAULT_CHANNEL_SEQUENCE_TOTAL_DURATION
        )
    }

    pub fn elapsed_since_slot_begin_in_tu(&self) -> usize {
        ((self.tsf_zero.elapsed().as_micros() % DEFAULT_SLOT_DURATION.as_micros()) / TU.as_micros())
            as usize
    }
    pub fn current_aw_in_chanseq(&self) -> usize {
        self.aw_seq_number() as usize % DEFAULT_SLOT_AW_COUNT
    }
    pub fn in_guard_interval(&self) -> bool {
        !(UNICAST_GUARD_INTERVAL_IN_TU
            ..(DEFAULT_SLOT_DURATION_IN_TU - UNICAST_GUARD_INTERVAL_IN_TU))
            .contains(&self.elapsed_since_slot_begin_in_tu())
    }
    pub fn time_to_next_slot_with_gi(&self) -> Duration {
        DEFAULT_SLOT_DURATION - duration_rem!(self.tsf_zero.elapsed(), DEFAULT_SLOT_DURATION)
            + UNICAST_GUARD_INTERVAL
    }
    pub fn time_to_slot_with_gi(&self, slot: usize) -> Duration {
        let current_slot = self.current_slot_in_chanseq();
        let temp = if current_slot >= slot {
            DEFAULT_SLOT_DURATION * (16 - (current_slot - slot) - 1) as u32
        } else {
            DEFAULT_SLOT_DURATION * ((slot - current_slot) - 1) as u32
        };
        temp + self.time_to_next_slot_with_gi()
    }
    fn channel_for_slot(&self, slot: usize) -> Channel {
        let (flags, channel) = self.channel_sequence[slot];
        Channel::Legacy { flags, channel }
    }
    pub fn overlaping_slots(&self, other: &SyncState) -> impl Iterator<Item = usize> {
        self.channel_sequence
            .into_iter()
            .zip(other.channel_sequence)
            .map(|((lhs_flags, lhs_channel), (rhs_flags, rhs_channel))| {
                (
                    Channel::Legacy {
                        flags: lhs_flags,
                        channel: lhs_channel,
                    }
                    .channel(),
                    Channel::Legacy {
                        flags: rhs_flags,
                        channel: rhs_channel,
                    }
                    .channel(),
                )
            })
            .enumerate()
            .filter_map(|(i, (lhs, rhs))| if lhs == rhs { Some(i) } else { None })
    }
    pub fn is_current_channel_different_from_previous(&self) -> bool {
        self.current_channel().channel() != self.previous_channel().channel()
    }
    pub fn aw_seq_number(&self) -> u16 {
        (self.tsf_zero.elapsed().as_micros() / AW_DURATION.as_micros()) as u16
    }

    pub fn current_channel(&self) -> Channel {
        self.channel_for_slot(self.current_slot_in_chanseq())
    }
    pub fn current_slot_in_chanseq(&self) -> usize {
        (self.elapsed_since_current_slot_zero().as_micros() / DEFAULT_SLOT_DURATION.as_micros())
            as usize
    }
    pub fn previous_channel(&self) -> Channel {
        self.channel_for_slot(self.previous_slot_in_chanseq())
    }
    pub fn previous_slot_in_chanseq(&self) -> usize {
        let current_slot = self.current_slot_in_chanseq();
        if current_slot > 0 {
            current_slot - 1
        } else {
            15
        }
    }
    pub fn next_channel(&self) -> Channel {
        self.channel_for_slot(self.next_slot_in_chanseq())
    }
    pub fn next_slot_in_chanseq(&self) -> usize {
        let current_slot = self.current_slot_in_chanseq();
        if current_slot < 15 {
            current_slot + 1
        } else {
            0
        }
    }

    pub fn remaining_aw_length(&self) -> Duration {
        duration_rem!(self.tsf_zero.elapsed(), AW_DURATION)
    }
    pub fn remaining_aw_length_in_tu(&self) -> u16 {
        (self.remaining_aw_length().as_micros() / TU.as_micros()) as u16
    }
    pub fn remaining_slot_length(&self) -> Duration {
        duration_rem!(
            self.elapsed_since_current_slot_zero(),
            DEFAULT_SLOT_DURATION
        )
    }
    pub fn remaining_slot_length_in_tu(&self) -> u16 {
        (self.remaining_slot_length().as_micros() / TU.as_micros()) as u16
    }

    pub async fn wait_for_next_slot(&self) -> Option<Channel> {
        let current_channel = self.current_channel();
        let next_channel = self.next_channel();
        sleep(self.remaining_slot_length()).await;
        if next_channel != current_channel {
            Some(next_channel)
        } else {
            None
        }
    }
    pub fn get_channel_sequence_legacy(&self) -> ChannelSequenceTLV {
        ChannelSequenceTLV {
            step_count: NonZeroU8::new(4).unwrap(),
            channel_sequence: ChannelSequence::Legacy(self.channel_sequence),
        }
    }
    pub fn get_channel_sequence_op_class(&self) -> ChannelSequenceTLV {
        ChannelSequenceTLV {
            step_count: NonZeroU8::new(4).unwrap(),
            channel_sequence: ChannelSequence::OpClass(self.channel_sequence.map(
                |(flags, channel)| {
                    (
                        channel,
                        match (Channel::Legacy { flags, channel }).channel() {
                            44 => 0x80,
                            6 => 0x51,
                            _ => 0x00,
                        },
                    )
                },
            )),
        }
    }
}
