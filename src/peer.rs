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

use awdl_frame_parser::{
    action_frame::{AWDLActionFrameSubType, DefaultAWDLActionFrame},
    common::AWDLDnsCompression,
    tlvs::{
        dns_sd::{dns_record::AWDLDnsRecord, DefaultServiceResponseTLV},
        sync_elect::{
            ElectionParametersTLV, ElectionParametersV2TLV, SynchronizationParametersTLV,
        },
        TLVReadIterator, AWDLTLV,
    },
};
use ieee80211::{common::TU, mgmt_frame::header::ManagementFrameHeader};
use mac_parser::MACAddress;
use tokio::time::Instant;

use crate::{state::ElectionState, sync::SyncState};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub address: MACAddress,
    pub election_state: ElectionState,
    pub last_psf_timestamp: Instant,
    pub last_mif_timestamp: Instant,
    pub sync_state: SyncState,
    pub is_airdrop: bool,
    pub last_tx_delta: Duration,
}
impl Peer {
    fn extract_tlvs(
        tlv_iter: TLVReadIterator<'_>,
    ) -> Option<(
        SynchronizationParametersTLV,
        ElectionParametersTLV,
        Option<ElectionParametersV2TLV>,
        Vec<DefaultServiceResponseTLV<'_>>,
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
        let is_airdrop = service_responses.into_iter().any(|service_response| {
            if let AWDLDnsRecord::PTR { domain_name } = service_response.record {
                domain_name.domain == AWDLDnsCompression::AirDropTcpLocal
            } else {
                false
            }
        });
        Some(Peer {
            address: management_frame_header.transmitter_address,
            election_state: election_parameters_v2_tlv.into(),
            last_psf_timestamp: Instant::now(),
            last_mif_timestamp: Instant::now(),
            sync_state: SyncState::new_with_sync_params_tlv_and_tx_delta(
                synchronization_parameters_tlv,
                awdl_af.tx_delta(),
            )?,
            is_airdrop,
            last_tx_delta: awdl_af.tx_delta(),
        })
    }
    pub async fn update_with_af(&mut self, awdl_af: DefaultAWDLActionFrame<'_>) {
        match awdl_af.subtype {
            AWDLActionFrameSubType::MIF => self.last_mif_timestamp = Instant::now(),
            AWDLActionFrameSubType::PSF => self.last_psf_timestamp = Instant::now(),
            _ => {}
        }
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
        self.sync_state = SyncState::new_with_sync_params_tlv_and_tx_delta(
            synchronization_parameters_tlv,
            awdl_af.tx_delta() + TU,
        )
        .unwrap();
        self.last_tx_delta = awdl_af.tx_delta();
    }
}
