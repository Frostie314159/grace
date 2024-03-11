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
        AW_DURATION, DEFAULT_CHANNEL_SEQUENCE_AW_COUNT, DEFAULT_CHANNEL_SEQUENCE_TOTAL_DURATION,
        DEFAULT_SLOT_DURATION,
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
    slot_zero_timestamp: Instant,
}
impl SyncState {
    pub fn new_with_default_chanseq() -> Self {
        Self {
            channel_sequence: {
                let mut chan_seq = [CHANNEL_44_FLAGS; 16];
                chan_seq[8] = CHANNEL_6_FLAGS;
                chan_seq
            },
            slot_zero_timestamp: Instant::now(),
        }
    }
    /// The Δt should be the sum Δt specified in the AF-Header and the time which has elapsed since the reception of that frame.
    pub fn new_with_sync_params_tlv_and_tx_delta(
        sync_params_tlv: SynchronizationParametersTLV,
        tx_delta: Duration,
    ) -> Option<Self> {
        let aws_since_slot_zero =
            sync_params_tlv.aw_seq_number % DEFAULT_CHANNEL_SEQUENCE_AW_COUNT as u16;
        let slot_zero_timestamp =
            Instant::now() - AW_DURATION * aws_since_slot_zero as u32 - tx_delta;

        let ChannelSequence::Legacy(channel_sequence) =
            sync_params_tlv.channel_sequence.channel_sequence
        else {
            return None;
        };
        Some(Self {
            channel_sequence,
            slot_zero_timestamp,
        })
    }
    pub fn sync_to(&mut self, other_state: SyncState) {
        // This is the advantage of our approach.
        self.slot_zero_timestamp = other_state.slot_zero_timestamp;
    }
    pub fn elapsed_since_current_slot_zero(&self) -> Duration {
        // If this doesn't work, change it back to div.
        duration_rem!(
            self.slot_zero_timestamp.elapsed(),
            DEFAULT_CHANNEL_SEQUENCE_TOTAL_DURATION
        )
    }
    pub fn current_slot_in_chanseq(&self) -> usize {
        (self.elapsed_since_current_slot_zero().as_micros() / DEFAULT_SLOT_DURATION.as_micros())
            as usize
    }
    pub fn previous_slot_in_chanseq(&self) -> usize {
        let current_slot = self.current_slot_in_chanseq();
        if current_slot > 0 {
            current_slot - 1
        } else {
            15
        }
    }
    pub fn next_slot_in_chanseq(&self) -> usize {
        let current_slot = self.current_slot_in_chanseq();
        if current_slot < 15 {
            current_slot + 1
        } else {
            0
        }
    }
    pub fn time_to_next_slot(&self) -> Duration {
        duration_rem!(
            self.elapsed_since_current_slot_zero(),
            DEFAULT_SLOT_DURATION
        )
    }
    fn channel_for_slot(&self, slot: usize) -> Channel {
        let (flags, channel) = self.channel_sequence[slot];
        Channel::Legacy { flags, channel }
    }
    pub fn current_channel(&self) -> Channel {
        self.channel_for_slot(self.current_slot_in_chanseq())
    }
    pub fn previous_channel(&self) -> Channel {
        self.channel_for_slot(self.previous_slot_in_chanseq())
    }
    pub fn next_channel(&self) -> Channel {
        self.channel_for_slot(self.next_slot_in_chanseq())
    }
    pub fn is_current_channel_different_from_previous(&self) -> bool {
        self.current_channel().channel() != self.previous_channel().channel()
    }
    pub async fn wait_for_next_slot(&self) -> Option<Channel> {
        let current_channel = self.current_channel();
        let next_channel = self.next_channel();
        sleep(self.time_to_next_slot()).await;
        if next_channel != current_channel {
            Some(next_channel)
        } else {
            None
        }
    }
    pub fn time_to_next_aw_in_tu(&self) -> u16 {
        (self.time_to_next_slot().as_micros() / TU.as_micros()) as u16
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
                |(_, channel)| {
                    (
                        channel,
                        match channel {
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
