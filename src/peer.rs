/*
    GrACE a FOSS implementation of the AWDL protocol.
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

use awdl_frame_parser::{
    action_frame::{AWDLActionFrameSubType, DefaultAWDLActionFrame},
    common::AWDLDnsCompression,
    tlvs::{
        dns_sd::{dns_record::AWDLDnsRecord, DefaultServiceResponseTLV},
        sync_elect::{
            channel::Channel, channel_sequence::ChannelSequence, ChannelSequenceTLV,
            ElectionParametersTLV, ElectionParametersV2TLV, SynchronizationParametersTLV,
        },
        TLVReadIterator, AWDLTLV,
    },
};
use ieee80211::{common::TU, mgmt_frame::header::ManagementFrameHeader};
use log::trace;
use mac_parser::MACAddress;
use tokio::time::Instant;

use crate::{
    constants::{AW_DURATION, DEFAULT_CHANNEL_SEQUENCE_AW_COUNT, DEFAULT_SLOT_DURATION},
    state::ElectionState,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SynchronizationState {
    pub tlv: SynchronizationParametersTLV,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub address: MACAddress,
    pub election_state: ElectionState,
    pub last_psf_timestamp: Instant,
    pub synchronization_state: SynchronizationState,
    pub is_airdrop: bool,
    pub last_tx_delta: Duration,
}
impl Peer {
    fn extract_tlvs<'a>(
        tlv_iter: TLVReadIterator<'a>,
    ) -> Option<(
        SynchronizationParametersTLV,
        ElectionParametersTLV,
        Option<ElectionParametersV2TLV>,
        Vec<DefaultServiceResponseTLV<'a>>,
    )> {
        let mut synchronization_parameters_tlv = None;
        let mut election_parameters_tlv = None;
        let mut election_parameters_v2_tlv = None;
        let mut service_responses = vec![];
        for tlv in tlv_iter {
            match tlv {
                AWDLTLV::SynchronizationParameters(sync_params) => {
                    synchronization_parameters_tlv = Some(sync_params)
                }
                AWDLTLV::ElectionParameters(election_params) => {
                    election_parameters_tlv = Some(election_params)
                }
                AWDLTLV::ElectionParametersV2(election_params_v2) => {
                    election_parameters_v2_tlv = Some(election_params_v2)
                }
                AWDLTLV::ServiceResponse(service_response) => {
                    service_responses.push(service_response);
                }
                _ => {}
            }
        }
        Some((
            synchronization_parameters_tlv?,
            election_parameters_tlv?,
            election_parameters_v2_tlv,
            service_responses,
        ))
    }
    pub fn new_with_af(
        management_frame_header: ManagementFrameHeader,
        awdl_af: DefaultAWDLActionFrame,
    ) -> Option<Self> {
        let (
            synchronization_parameters_tlv,
            _election_parameters,
            Some(election_parameters_v2_tlv),
            service_responses,
        ) = Self::extract_tlvs(awdl_af.tagged_data)?
        else {
            return None;
        };
        let is_airdrop = service_responses
            .into_iter()
            .find(|service_response| {
                if let AWDLDnsRecord::PTR { domain_name } = service_response.record {
                    domain_name.domain == AWDLDnsCompression::AirDropTcpLocal
                } else {
                    false
                }
            })
            .is_some();
        Some(Peer {
            address: management_frame_header.transmitter_address,
            election_state: election_parameters_v2_tlv.into(),
            last_psf_timestamp: Instant::now(),
            synchronization_state: SynchronizationState {
                tlv: synchronization_parameters_tlv,
            },
            is_airdrop,
            last_tx_delta: awdl_af.tx_delta(),
        })
    }
    pub async fn update_with_af(&mut self, awdl_af: DefaultAWDLActionFrame<'_>) {
        self.last_psf_timestamp = Instant::now();
        let Some((
            synchronization_parameters_tlv,
            _election_parameters,
            Some(election_parameters_v2_tlv),
            _service_responses,
        )) = Self::extract_tlvs(awdl_af.tagged_data)
        else {
            return;
        };
        self.election_state = election_parameters_v2_tlv.into();
        self.synchronization_state = SynchronizationState {
            tlv: synchronization_parameters_tlv,
        };
        self.last_tx_delta = awdl_af.tx_delta();
        if self.address == self.election_state.sync_master_address {
            /* trace!(
                "Current slot in channel sequence: {:02} for peer {} with aw seq {}",
                self.current_slot_in_chanseq(),
                self.address,
                self.synchronization_state.tlv.aw_seq_number
            ); */
        }
    }
    pub fn current_slot_in_chanseq(&self) -> usize {
        self.current_aw_in_chanseq() / 4
    }
    pub fn current_aw_in_chanseq(&self) -> usize {
        let aws_since_transmission = ((self.last_psf_timestamp.elapsed() + self.last_tx_delta + TU)
            .as_micros()
            / AW_DURATION.as_micros()) as u16; // One TU processing delta
        (self
            .synchronization_state
            .tlv
            .aw_seq_number
            .wrapping_add(aws_since_transmission)
            % 64) as usize
    }
    pub fn time_to_next_slot(&self) -> () {
        let _delta = self.last_tx_delta + self.last_psf_timestamp.elapsed() + TU; // One TU processing delta.
        let _slot_period = TU
            * self.synchronization_state.tlv.aw_period.into()
            * self.synchronization_state.tlv.presence_mode.into();
    }
    pub fn time_since_slot_zero(&self) -> Duration {
        DEFAULT_SLOT_DURATION * self.current_slot_in_chanseq() as u32
    }
    pub fn current_channel(&self) -> u8 {
        let ChannelSequence::Legacy(legacy_channel_sequence) = self
            .synchronization_state
            .tlv
            .channel_sequence
            .channel_sequence
        else {
            panic!()
        };
        let (flags, channel) = legacy_channel_sequence[self.current_slot_in_chanseq()];
        Channel::Legacy { flags, channel }.channel()
    }
}
