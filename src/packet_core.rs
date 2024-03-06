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

use std::{cmp::Ordering, collections::HashMap, iter::Empty, marker::PhantomData, time::Duration};

use awdl_frame_parser::{
    action_frame::{AWDLActionFrame, AWDLActionFrameSubType, DefaultAWDLActionFrame},
    common::AWDLStr,
    data_frame::AWDLDataFrame,
    tlvs::{
        sync_elect::{channel::Channel, channel_sequence::ChannelSequence},
        AWDLTLV,
    },
};
use circular_buffer::CircularBuffer;
use ethernet::{Ethernet2Frame, Ethernet2Header, OwnedEthernet2Frame};
use ieee80211::{
    common::TU,
    data_frame::{
        builder::DataFrameBuilder, header::DataFrameHeader, DataFrame, DataFrameReadPayload,
    },
    elements::rates::EncodedRate,
    mgmt_frame::{
        body::{action::ActionFrameBody, ManagementFrameBody, ToManagementFrameBody},
        header::ManagementFrameHeader,
        ManagementFrame,
    },
    IEEE80211Frame, ToFrame,
};
use log::{debug, info, trace};
use mac_parser::{MACAddress, BROADCAST, ZERO};
use rtap::frame::{self, RadiotapFrame};
use scroll::{ctx::MeasureWith, Pread, Pwrite};
use tokio::{process::Command, select, sync::RwLock, time::interval};

use crate::{
    constants::DEFAULT_SLOT_DURATION, hals::{EthernetInterface, HostEthernetInterface, HostWiFiInterface, WiFiInterface}, llc::AWDLLLCFrame, peer::{self, Peer}, state::SelfState, util::{ipv6_addr_from_hw_address, APPLE_OUI}
};

const AWDL_BSSID: MACAddress = MACAddress::new([0x00, 0x25, 0x00, 0xff, 0x94, 0x73]);

const PEER_REMOVE_TIMEOUT: Duration = Duration::from_secs(3);

pub struct PacketCore {
    wifi_interface: HostWiFiInterface,
    ethernet_interface: HostEthernetInterface,
    peer_list: RwLock<HashMap<MACAddress, Peer>>,
    self_state: SelfState,
}
impl PacketCore {
    pub async fn new(interface_name: &str, hardware_address: MACAddress) -> Self {
        Self {
            wifi_interface: HostWiFiInterface::new(interface_name)
                .expect("Failed to initialize wifi interface."),
            ethernet_interface: HostEthernetInterface::new(hardware_address)
                .expect("Failed to initialize ethernet interface."),
            peer_list: RwLock::new(HashMap::new()),
            self_state: SelfState::new(hardware_address),
        }
    }
    async fn process_ethernet_frame<const N: usize>(
        &mut self,
        buf: &[u8],
        unicast_queue: &mut CircularBuffer<N, OwnedEthernet2Frame>,
        multicast_queue: &mut CircularBuffer<N, OwnedEthernet2Frame>,
    ) {
        let Ok(ethernet_frame) = buf.pread::<Ethernet2Frame>(0) else {
            debug!("Invalid ethernet frame received.");
            return;
        };
        if ethernet_frame.header.dst.is_multicast() {
            multicast_queue
        } else {
            if !self
                .peer_list
                .read()
                .await
                .contains_key(&ethernet_frame.header.dst)
            {
                return;
            }
            unicast_queue
        }
        .push_back(OwnedEthernet2Frame {
            header: ethernet_frame.header,
            payload: ethernet_frame.payload.to_vec(),
        });
    }
    fn is_wifi_frame_valid(&self, wifi_frame: &IEEE80211Frame<'_>) -> bool {
        // BSSID matching
        match wifi_frame {
            IEEE80211Frame::Data(data_frame) => {
                if data_frame.header.bssid() != Some(&AWDL_BSSID) {
                    return false;
                }
            }
            IEEE80211Frame::Management(mgmt_frame) => {
                if mgmt_frame.header.bssid != AWDL_BSSID {
                    return false;
                }
            }
        }
        // Check fcf flags.
        let fcf_flags = wifi_frame.get_fcf().flags();
        if fcf_flags.to_ds() || fcf_flags.from_ds() {
            debug!(
                "WiFi frame was sent with DS status: To DS: {}, From DS: {}.",
                fcf_flags.to_ds(),
                fcf_flags.from_ds()
            );
            return false;
        }
        true
    }
    async fn send_wifi_msdu_to_tap_interface(
        &mut self,
        destination_address: MACAddress,
        source_address: MACAddress,
        payload: &[u8],
    ) {
        let Ok(llc_frame) = payload.pread::<AWDLLLCFrame<&[u8]>>(0) else {
            return;
        };
        let Ok(awdl_data_frame) = llc_frame.payload.pread::<AWDLDataFrame<&[u8]>>(0) else {
            return;
        };
        let mut buf = [0x00u8; 1518];
        let Ok(len) = buf.pwrite(
            Ethernet2Frame {
                header: Ethernet2Header {
                    dst: destination_address,
                    src: source_address,
                    ether_type: awdl_data_frame.ether_type,
                },
                payload: awdl_data_frame.payload,
            },
            0,
        ) else {
            return;
        };
        let _ = self.ethernet_interface.send(&buf[0..len]).await;
    }
    async fn process_wifi_data_frame(
        &mut self,
        data_frame: DataFrame<'_, DataFrameReadPayload<'_>>,
    ) {
        let Some(payload) = data_frame.payload else {
            debug!(
                "Data frame from: {} didn't contain a payload.",
                data_frame.header.transmitter_address()
            );
            return;
        };
        match payload {
            DataFrameReadPayload::Single(single_payload) => {
                self.send_wifi_msdu_to_tap_interface(
                    *data_frame.header.destination_address().unwrap(),
                    *data_frame.header.source_address().unwrap(),
                    single_payload,
                )
                .await
            }
            DataFrameReadPayload::AMSDU(amsdu_payload) => {
                for amsdu_subframe in amsdu_payload {
                    self.send_wifi_msdu_to_tap_interface(
                        amsdu_subframe.destination_address,
                        amsdu_subframe.source_address,
                        amsdu_subframe.payload,
                    )
                    .await;
                }
            }
        }
    }
    async fn process_wifi_action_frame(
        &mut self,
        management_frame_header: ManagementFrameHeader,
        action_frame_body: &[u8],
    ) {
        let Ok(awdl_af) = action_frame_body.pread::<DefaultAWDLActionFrame>(0) else {
            return;
        };
        let mut peer_list = self.peer_list.write().await;
        if let Some(peer) = peer_list.get_mut(&management_frame_header.transmitter_address) {
            peer.update_with_af(awdl_af).await;
        } else {
            let Some(peer) = Peer::new_with_af(management_frame_header, awdl_af) else {
                return;
            };
            peer_list.insert(management_frame_header.transmitter_address, peer);
            self.ethernet_interface
                .add_peer_to_neighbor_table(management_frame_header.transmitter_address);
            info!(
                "Added peer: {} to peer list.",
                management_frame_header.transmitter_address
            );
        }
    }
    async fn process_wifi_frame(&mut self, buf: &[u8]) {
        let Ok(radiotap_frame) = buf.pread::<RadiotapFrame>(0) else {
            return;
        };
        let Ok(wifi_frame) = radiotap_frame.payload.pread::<IEEE80211Frame>(0) else {
            // trace!("Invalid wifi frame received.");
            return;
        };
        if !self.is_wifi_frame_valid(&wifi_frame) {
            return;
        }
        match wifi_frame {
            IEEE80211Frame::Data(data_frame) => {
                self.process_wifi_data_frame(data_frame).await;
            }
            IEEE80211Frame::Management(ManagementFrame {
                header: management_frame_header,
                body:
                    ManagementFrameBody::Action(ActionFrameBody::VendorSpecific {
                        oui: APPLE_OUI,
                        payload,
                    }),
            }) => {
                self.process_wifi_action_frame(management_frame_header, payload)
                    .await;
            }
            _ => {}
        }
    }
    async fn purge_stale_peers(&mut self) {
        self.peer_list.write().await.retain(|address, peer| {
            let is_peer_still_active = peer.last_psf_timestamp.elapsed() < PEER_REMOVE_TIMEOUT;

            if !is_peer_still_active {
                info!("Removing peer {address} from peer list due to inactivity.");
                self.ethernet_interface.add_peer_to_neighbor_table(*address);
            }

            is_peer_still_active
        });
    }
    async fn run_election(&mut self) {
        let peer_list = self.peer_list.read().await;
        if peer_list.len() != 0 {
            let (master, master_metric) = peer_list
                .iter()
                .map(|(key, value)| (key, value.election_state.self_metric))
                .fold(
                    (ZERO, 0),
                    |(current_address, current_metric), (peer_address, peer_metric)| {
                        match peer_metric.cmp(&current_metric) {
                            Ordering::Less | Ordering::Equal => (current_address, current_metric),
                            Ordering::Greater => (*peer_address, peer_metric),
                        }
                    },
                );
            let master_peer = &peer_list[&master];
            if master_metric < self.self_state.election_state.self_metric {
                self.self_state.set_master_to_self();
            } else {
                self.self_state
                    .sync_state
                    .reset_with_current_aw(master_peer.current_aw_in_chanseq() as u8);
            }
            if self.self_state.election_state.sync_master_address != master {
                trace!("Current master is: {master}");
                self.self_state.election_state.sync_master_address = master;
                self.self_state.election_state.top_master_address = master_peer.address;
                self.self_state.election_state.master_metric =
                    master_peer.election_state.self_metric;
                self.self_state.election_state.master_counter =
                    master_peer.election_state.self_counter;
            }
        }
    }
    async fn send_psf(&mut self) {
        let awdl_af = AWDLActionFrame {
            subtype: AWDLActionFrameSubType::PSF,
            phy_tx_time: Duration::default(),
            target_tx_time: Duration::default(),
            tagged_data: self.self_state.generate_psf_body(),
        };
        let wifi_frame = ManagementFrame {
            header: ManagementFrameHeader {
                receiver_address: BROADCAST,
                transmitter_address: self.self_state.address,
                bssid: AWDL_BSSID,
                ..Default::default()
            },
            body: ActionFrameBody::VendorSpecific {
                oui: APPLE_OUI,
                payload: awdl_af,
            }
            .to_management_frame_body(),
        }
        .to_frame();
        let mut frame_buf = vec![0x00; wifi_frame.measure_with(&true) + 10];
        frame_buf
            .as_mut_slice()
            .pwrite_with(wifi_frame, 10, true)
            .unwrap();
        frame_buf[2] = 10;
        frame_buf[4] = 0x06;
        frame_buf[8] = 0x10;
        frame_buf[9] = EncodedRate::from_rate_in_kbps(54000, false).into_bits();
        let _ = self.wifi_interface.send(&frame_buf).await;
        self.self_state.sequence_number += 1;
    }
    async fn send_mif(&mut self) {
        let awdl_af = AWDLActionFrame {
            subtype: AWDLActionFrameSubType::MIF,
            phy_tx_time: Duration::default(),
            target_tx_time: Duration::default(),
            tagged_data: self.self_state.generate_mif_body(),
        };
        let wifi_frame = ManagementFrame {
            header: ManagementFrameHeader {
                receiver_address: BROADCAST,
                transmitter_address: self.self_state.address,
                bssid: AWDL_BSSID,
                ..Default::default()
            },
            body: ActionFrameBody::VendorSpecific {
                oui: APPLE_OUI,
                payload: awdl_af,
            }
            .to_management_frame_body(),
        }
        .to_frame();
        let mut frame_buf = vec![0x00; wifi_frame.measure_with(&true) + 10];
        frame_buf
            .as_mut_slice()
            .pwrite_with(wifi_frame, 10, true)
            .unwrap();
        frame_buf[2] = 10;
        frame_buf[4] = 0x06;
        frame_buf[8] = 0x10;
        frame_buf[9] = EncodedRate::from_rate_in_kbps(54000, false).into_bits();
        let _ = self.wifi_interface.send(&frame_buf).await;
        self.self_state.sequence_number += 1;
    }
    async fn go_to_new_channel(channel: u8) {
        Command::new("iw")
            .args([
                "dev",
                "wlan1",
                "set",
                "channel",
                channel.to_string().as_str(),
            ])
            .spawn()
            .unwrap()
            .wait()
            .await;
        trace!("Switched channel.");
    }
    async fn send_unicast_data_frames<const N: usize>(
        &mut self,
        unicast_queue: &mut CircularBuffer<N, OwnedEthernet2Frame>,
    ) {
        let peer_list = self.peer_list.read().await;
        let mut not_transmitted_frames = Vec::new();
        while let Some(frame) = unicast_queue.pop_front() {
            let Some(peer) = peer_list.get(&frame.header.dst) else {
                continue;
            };
            if self.self_state.sync_state.current_channel() != peer.current_channel() {
                // Try again next time.
                not_transmitted_frames.push(frame);
                continue;
            }
            let awdl_data_frame = AWDLDataFrame {
                ether_type: frame.header.ether_type,
                sequence_number: self.self_state.sequence_number,
                payload: frame.payload.as_slice(),
            };
            let llc_frame = AWDLLLCFrame {
                ssap: 0xaa,
                dsap: 0xaa,
                payload: awdl_data_frame,
            };
            let wifi_frame = DataFrame {
                header: DataFrameHeader {
                    address_1: frame.header.dst,
                    address_2: frame.header.src,
                    address_3: AWDL_BSSID,
                    ..Default::default()
                },
                payload: Some(llc_frame),
                _phantom: PhantomData,
            }
            .to_frame();

            let mut frame_buf = vec![0x00; wifi_frame.measure_with(&true) + 10];
            frame_buf
                .as_mut_slice()
                .pwrite_with(wifi_frame, 10, true)
                .unwrap();
            frame_buf[2] = 10;
            frame_buf[4] = 0x06;
            frame_buf[8] = 0x10;
            frame_buf[9] = EncodedRate::from_rate_in_kbps(54000, false).into_bits();
            let _ = self.wifi_interface.send(&frame_buf).await;
            trace!("Transmitted data frame.");
            self.self_state.sequence_number += 1;
        }
        not_transmitted_frames
            .into_iter()
            .for_each(|frame| unicast_queue.push_back(frame));
    }
    async fn send_multicast_data_frames<const N: usize>(&mut self, multicast_queue: &mut CircularBuffer<N, OwnedEthernet2Frame>) {
        while let Some(frame) = multicast_queue.pop_front() {
            let awdl_data_frame = AWDLDataFrame {
                ether_type: frame.header.ether_type,
                sequence_number: self.self_state.sequence_number,
                payload: frame.payload.as_slice(),
            };
            let llc_frame = AWDLLLCFrame {
                ssap: 0xaa,
                dsap: 0xaa,
                payload: awdl_data_frame,
            };
            let wifi_frame = DataFrame {
                header: DataFrameHeader {
                    address_1: frame.header.dst,
                    address_2: frame.header.src,
                    address_3: AWDL_BSSID,
                    ..Default::default()
                },
                payload: Some(llc_frame),
                _phantom: PhantomData,
            }
            .to_frame();

            let mut frame_buf = vec![0x00; wifi_frame.measure_with(&true) + 10];
            frame_buf
                .as_mut_slice()
                .pwrite_with(wifi_frame, 10, true)
                .unwrap();
            frame_buf[2] = 10;
            frame_buf[4] = 0x06;
            frame_buf[8] = 0x10;
            frame_buf[9] = EncodedRate::from_rate_in_kbps(12000, false).into_bits();
            let _ = self.wifi_interface.send(&frame_buf).await;
            trace!("Transmitted data frame.");
            self.self_state.sequence_number += 1;
        }
    }
    pub async fn run(mut self) {
        let mut wifi_buf = [0x00; 8192];
        let mut ethernet_buf = [0x00; 1450];

        let mut purge_timer = interval(Duration::from_millis(500));
        let mut election_timer = interval(Duration::from_millis(500));
        let mut psf_timer = interval(TU * 110);
        let mut mif_timer = interval(DEFAULT_SLOT_DURATION * 8);

        let mut unicast_queue: CircularBuffer<16, OwnedEthernet2Frame> = CircularBuffer::new();
        let mut multicast_queue: CircularBuffer<16, OwnedEthernet2Frame> = CircularBuffer::new();
        loop {
            select! {
                _ = psf_timer.tick() => self.send_psf().await,
                ret = self.wifi_interface.recv(&mut wifi_buf) => {
                    self.process_wifi_frame(&wifi_buf[..ret.expect("Failed to read from wifi interface.")]).await
                },
                ret = self.ethernet_interface.recv(&mut ethernet_buf) => {
                    self.process_ethernet_frame(&ethernet_buf[..ret.expect("Failed to read from ethernet interface.")], &mut unicast_queue, &mut multicast_queue).await
                }
                _ = purge_timer.tick() => self.purge_stale_peers().await,
                _ = election_timer.tick() => self.run_election().await,
                new_channel = self.self_state.sync_state.wait_for_next_slot() => {
                    if let Some(new_channel) = new_channel {
                        Self::go_to_new_channel(new_channel).await;
                    }
                    let current_slot = self.self_state.sync_state.current_slot_in_chanseq();
                    if current_slot == 0 || current_slot == 10 {
                        self.send_multicast_data_frames(&mut multicast_queue).await;
                    }
                    self.send_unicast_data_frames(&mut unicast_queue).await;
                }
                _ = mif_timer.tick() => self.send_mif().await
            }
        }
    }
}
