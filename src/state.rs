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

use awdl_frame_parser::{
    common::{AWDLDnsCompression, AWDLDnsName, AWDLStr, AWDLVersion},
    tlvs::{
        data_path::{
            ampdu_parameters::AMpduParameters, ht_capabilities_info::HTCapabilitiesInfo,
            DataPathExtendedFlags, DataPathFlags, DataPathStateTLV, HTCapabilitiesTLV,
        },
        dns_sd::{ArpaTLV, ServiceParametersTLV},
        sync_elect::{
            ElectionParametersTLV, ElectionParametersV2TLV, SynchronizationParametersTLV,
        },
        version::{AWDLDeviceClass, VersionTLV},
        AWDLTLV,
    },
};
use mac_parser::MACAddress;
use std::{
    iter::{empty, Empty},
    time::Instant,
};

use crate::{constants::AW_DURATION, sync::SyncState};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ElectionState {
    pub self_metric: u32,
    pub self_counter: u32,
    pub master_metric: u32,
    pub master_counter: u32,
    pub top_master_address: MACAddress,
    pub sync_master_address: MACAddress,
}
impl ElectionState {
    pub const fn new(self_address: MACAddress) -> Self {
        Self {
            self_metric: 500,
            self_counter: 60,
            master_metric: 0,
            master_counter: 0,
            top_master_address: self_address,
            sync_master_address: self_address,
        }
    }
}
impl From<ElectionParametersV2TLV> for ElectionState {
    fn from(value: ElectionParametersV2TLV) -> Self {
        Self {
            self_metric: value.self_metric,
            self_counter: value.self_counter,
            master_metric: value.master_metric,
            master_counter: value.master_counter,
            top_master_address: value.master_address,
            sync_master_address: value.sync_address,
        }
    }
}
pub struct SelfState {
    pub election_state: ElectionState,
    pub sync_state: SyncState,
    pub init_timestamp: Instant,
    pub address: MACAddress,
    pub sequence_number: u16,
}
impl SelfState {
    pub fn new(self_address: MACAddress) -> Self {
        Self {
            election_state: ElectionState::new(self_address),
            sync_state: SyncState::new_with_default_chanseq(),
            init_timestamp: Instant::now(),
            address: self_address,
            sequence_number: 0,
        }
    }
    fn get_aw_seq_number(&self) -> u16 {
        (self.init_timestamp.elapsed().as_micros() / AW_DURATION.as_micros()) as u16 % u16::MAX
    }
    pub fn set_master_to_self(&mut self) {
        self.election_state.top_master_address = self.address;
        self.election_state.sync_master_address = self.address;
    }
    pub fn are_we_master(&self) -> bool {
        self.election_state.sync_master_address == self.address
    }
    fn generate_sync_params(&self) -> SynchronizationParametersTLV {
        SynchronizationParametersTLV {
            next_channel: self.sync_state.next_channel().channel(),
            tx_counter: self.sync_state.time_to_next_aw_in_tu(),
            master_channel: 6,
            aw_period: 16,
            af_period: 110,
            awdl_flags: 0x1800,
            aw_ext_length: 16,
            aw_common_length: 16,
            remaining_aw_length: 0,
            min_ext_count: 3,
            max_multicast_ext_count: 3,
            max_unicast_ext_count: 3,
            max_af_ext_count: 3,
            master_address: self.election_state.sync_master_address,
            ap_beacon_alignment_delta: 0,
            presence_mode: 4,
            aw_seq_number: self.get_aw_seq_number(),
            channel_sequence: self.sync_state.get_channel_sequence_legacy(),
            ..Default::default()
        }
    }
    fn generate_election_parameters(&self) -> ElectionParametersTLV {
        ElectionParametersTLV {
            flags: 0x00,
            id: 0x00,
            distance_to_master: 0,
            master_address: self.election_state.sync_master_address,
            master_metric: self.election_state.master_metric,
            self_metric: self.election_state.self_metric,
        }
    }
    fn generate_election_parameters_v2(&self) -> ElectionParametersV2TLV {
        ElectionParametersV2TLV {
            master_address: self.election_state.top_master_address,
            sync_address: self.election_state.sync_master_address,
            master_counter: self.election_state.master_counter,
            distance_to_master: 0,
            master_metric: self.election_state.master_metric,
            self_metric: self.election_state.self_metric,
            election_id: 0,
            self_counter: self.election_state.self_counter,
        }
    }
    fn generate_version_tlv(&self) -> VersionTLV {
        VersionTLV {
            version: AWDLVersion { major: 6, minor: 9 },
            device_class: AWDLDeviceClass::MacOS,
        }
    }
    fn generate_arpa_tlv(&self) -> ArpaTLV<Vec<AWDLStr>> {
        ArpaTLV {
            arpa: AWDLDnsName {
                labels: ["FCK-APL".into()].to_vec(),
                domain: AWDLDnsCompression::Local,
            },
        }
    }
    fn generate_service_parameters(&self) -> ServiceParametersTLV<Empty<u8>> {
        ServiceParametersTLV {
            sui: 69,
            encoded_values: empty(),
        }
    }
    fn generate_data_path_state(&self) -> DataPathStateTLV {
        DataPathStateTLV {
            awdl_address: Some(self.address),
            country_code: Some(['D', 'E']),
            flags: DataPathFlags {
                airplay_solo_mode_support: true,
                umi_support: true,
                ..Default::default()
            },
            extended_flags: Some(DataPathExtendedFlags::default()),
            ..Default::default()
        }
    }
    fn generate_ht_capabilities(&self) -> HTCapabilitiesTLV {
        HTCapabilitiesTLV {
            ht_capabilities_info: HTCapabilitiesInfo::from_bits(0x11ce),
            a_mpdu_parameters: AMpduParameters::from_bits(0x1b),
            rx_spatial_stream_count: 1,
        }
    }
    pub fn generate_psf_body<'b>(
        &self,
    ) -> [AWDLTLV<'b, Empty<MACAddress>, Vec<AWDLStr>, Empty<u8>>; 7] {
        [
            AWDLTLV::SynchronizationParameters(self.generate_sync_params()),
            AWDLTLV::ElectionParameters(self.generate_election_parameters()),
            AWDLTLV::ChannelSequence(self.sync_state.get_channel_sequence_op_class()),
            AWDLTLV::ElectionParametersV2(self.generate_election_parameters_v2()),
            AWDLTLV::ServiceParameters(self.generate_service_parameters()),
            AWDLTLV::DataPathState(self.generate_data_path_state()),
            AWDLTLV::Version(self.generate_version_tlv()),
        ]
    }
    pub fn generate_mif_body(
        &self,
    ) -> [AWDLTLV<'_, Empty<MACAddress>, Vec<AWDLStr>, Empty<u8>>; 9] {
        [
            AWDLTLV::SynchronizationParameters(self.generate_sync_params()),
            AWDLTLV::ElectionParameters(self.generate_election_parameters()),
            AWDLTLV::ChannelSequence(self.sync_state.get_channel_sequence_op_class()),
            AWDLTLV::ElectionParametersV2(self.generate_election_parameters_v2()),
            AWDLTLV::ServiceParameters(self.generate_service_parameters()),
            AWDLTLV::HTCapabilities(self.generate_ht_capabilities()),
            AWDLTLV::Arpa(self.generate_arpa_tlv()),
            AWDLTLV::DataPathState(self.generate_data_path_state()),
            AWDLTLV::Version(self.generate_version_tlv()),
        ]
    }
}
