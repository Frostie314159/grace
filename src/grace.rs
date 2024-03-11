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

use std::{collections::HashMap, sync::Arc, time::Duration};

use awdl_frame_parser::{action_frame::DefaultAWDLActionFrame, data_frame::AWDLDataFrame};
use ethernet::{Ethernet2Frame, Ethernet2Header};
use ieee80211::{
    common::TU, data_frame::{DataFrame, DataFrameReadPayload}, mgmt_frame::{
        body::{action::ActionFrameBody, ManagementFrameBody},
        header::ManagementFrameHeader,
        ManagementFrame,
    }, IEEE80211Frame
};
use log::{info, trace};
use mac_parser::MACAddress;
use rtap::{field_types::RadiotapField, frame::RadiotapFrame};
use scroll::{Pread, Pwrite};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    join, select, spawn,
    sync::{Mutex, Notify, RwLock},
    time::{interval, sleep},
};

use crate::{
    constants::DEFAULT_SLOT_DURATION,
    hals::{ChannelWidth, IPv6ControlInterface, WiFiControlInterface},
    llc::AWDLLLCFrame,
    peer::Peer,
    state::SelfState,
    util::APPLE_OUI,
};

const PEER_REMOVE_TIMEOUT: Duration = Duration::from_secs(3);

const AWDL_BSSID: MACAddress = MACAddress::new([0x00, 0x25, 0x00, 0xff, 0x94, 0x73]);

struct SharedState<IPv6ControlInterfaceInstance: IPv6ControlInterface> {
    peers: RwLock<HashMap<MACAddress, Peer>>,
    ipv6_control_interface: Mutex<IPv6ControlInterfaceInstance>,
    self_state: RwLock<SelfState>,
    sync_change_notify: Notify,
}
impl<IPv6ControlInterfaceInstance: IPv6ControlInterface> SharedState<IPv6ControlInterfaceInstance> {
    pub fn new(
        ipv6_control_interface: IPv6ControlInterfaceInstance,
        mac_address: MACAddress,
    ) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            ipv6_control_interface: Mutex::new(ipv6_control_interface),
            self_state: RwLock::new(SelfState::new(mac_address)),
            sync_change_notify: Notify::new(),
        }
    }
}
fn extract_fields_from_radiotap_iter(
    radiotap_iter: &mut impl Iterator<Item = RadiotapField>,
) -> (Option<i8>,) {
    let mut rssi = None;
    radiotap_iter.for_each(|field| match field {
        RadiotapField::AntennaSignal { signal } => rssi = Some(signal),
        _ => {}
    });
    (rssi,)
}
async fn send_msdu_to_tap_interface(
    ethernet_write_half: &mut WriteHalf<impl AsyncWrite + 'static>,
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
    let ethernet_frame = Ethernet2Frame {
        header: Ethernet2Header {
            dst: destination_address,
            src: source_address,
            ether_type: awdl_data_frame.ether_type,
        },
        payload: awdl_data_frame.payload,
    };
    let mut buf = [0x00u8; 1518];
    let Ok(len) = buf.pwrite(ethernet_frame, 0) else {
        return;
    };
    let _ = ethernet_write_half.write(&buf[..len]).await;
}
async fn process_awdl_data_frame(
    ethernet_write_half: &mut WriteHalf<impl AsyncWrite + 'static>,
    data_frame: DataFrame<'_>,
) {
    // Discard NDPs.
    let Some(data_frame_payload) = data_frame.payload else {
        return;
    };
    match data_frame_payload {
        DataFrameReadPayload::Single(payload) => {
            send_msdu_to_tap_interface(
                ethernet_write_half,
                *data_frame.header.receiver_address(),
                *data_frame.header.transmitter_address(),
                payload,
            )
            .await
        }
        DataFrameReadPayload::AMSDU(subframe_iterator) => {
            for sub_frame in subframe_iterator {
                send_msdu_to_tap_interface(
                    ethernet_write_half,
                    sub_frame.destination_address,
                    sub_frame.source_address,
                    sub_frame.payload,
                )
                .await;
            }
        }
    }
}
async fn process_awdl_action_frame(
    shared_state: &Arc<SharedState<impl IPv6ControlInterface>>,
    header: ManagementFrameHeader,
    payload: &[u8],
) {
    let Ok(awdl_action_frame) = payload.pread::<DefaultAWDLActionFrame>(0) else {
        return;
    };
    let mut peer_list = shared_state.peers.write().await;

    if let Some(peer) = peer_list.get_mut(&header.transmitter_address) {
        peer.update_with_af(awdl_action_frame).await;
    } else {
        let Some(peer) = Peer::new_with_af(header, awdl_action_frame) else {
            return;
        };
        info!("Adding peer {} to peer list.", header.transmitter_address);
        peer_list.insert(header.transmitter_address, peer);
        shared_state
            .ipv6_control_interface
            .lock()
            .await
            .add_peer_to_neighbor_table(header.transmitter_address)
            .await;
    }
}
async fn process_wifi_frame(
    shared_state: &Arc<SharedState<impl IPv6ControlInterface>>,
    ethernet_write_half: &mut WriteHalf<impl AsyncWrite + Send + Sync + 'static>,
    buf: &[u8],
) {
    let Ok(radiotap_frame) = buf.pread::<RadiotapFrame>(0) else {
        return;
    };
    let (_rssi,) = extract_fields_from_radiotap_iter(&mut radiotap_frame.get_field_iter());
    let Ok(wifi_frame) = radiotap_frame.payload.pread::<IEEE80211Frame>(0) else {
        return;
    };
    let fcf_flags = wifi_frame.get_fcf().flags();

    // AWDL frames are always neither to nor from DS, since it's Ad-Hoc.
    if fcf_flags.to_ds() || fcf_flags.from_ds() {
        return;
    }

    match wifi_frame {
        IEEE80211Frame::Management(ManagementFrame {
            header,
            body:
                ManagementFrameBody::Action(ActionFrameBody::VendorSpecific {
                    oui: APPLE_OUI,
                    payload,
                }),
        }) => process_awdl_action_frame(shared_state, header, payload).await,
        IEEE80211Frame::Data(data_frame) => {
            if data_frame.header.bssid().copied() == Some(AWDL_BSSID) {
                process_awdl_data_frame(ethernet_write_half, data_frame).await;
            }
        }
        _ => {}
    }
}
fn is_peer_more_eligable_for_master(lhs: &Peer, rhs: &Peer) -> bool {
    lhs.election_state.self_metric < rhs.election_state.self_metric
}

pub struct Grace<
    WiFiDataInterface: AsyncRead + AsyncWrite,
    WiFiControlInterfaceInstance: WiFiControlInterface,
    EthernetDataInterface: AsyncRead + AsyncWrite,
    IPv6ControlInterfaceInstance: IPv6ControlInterface,
> {
    wifi_data_interface: (ReadHalf<WiFiDataInterface>, WriteHalf<WiFiDataInterface>),
    wifi_control_interface: WiFiControlInterfaceInstance,
    ethernet_data_interface: (
        ReadHalf<EthernetDataInterface>,
        WriteHalf<EthernetDataInterface>,
    ),
    ipv6_control_interface: IPv6ControlInterfaceInstance,
}
impl<
        WiFiDataInterface: AsyncRead + AsyncWrite + Send + Sync + 'static,
        WiFiControlInterfaceInstance: WiFiControlInterface + 'static,
        EthernetDataInterface: AsyncRead + AsyncWrite + Send + Sync + 'static,
        IPv6ControlInterfaceInstance: IPv6ControlInterface + 'static,
    >
    Grace<
        WiFiDataInterface,
        WiFiControlInterfaceInstance,
        EthernetDataInterface,
        IPv6ControlInterfaceInstance,
    >
{
    #[inline]
    pub fn new(
        wifi_interface: (
            WiFiControlInterfaceInstance,
            ReadHalf<WiFiDataInterface>,
            WriteHalf<WiFiDataInterface>,
        ),
        ethernet_interface: (
            IPv6ControlInterfaceInstance,
            ReadHalf<EthernetDataInterface>,
            WriteHalf<EthernetDataInterface>,
        ),
    ) -> Self {
        Self {
            wifi_data_interface: (wifi_interface.1, wifi_interface.2),
            wifi_control_interface: wifi_interface.0,
            ethernet_data_interface: (ethernet_interface.1, ethernet_interface.2),
            ipv6_control_interface: ethernet_interface.0,
        }
    }
    async fn purge_stale_peers_task(shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>) {
        // We check every 0.5s if peers have become stale. Should be sufficient.
        // Making this duration smaller will cause lock contention.
        let mut interval = interval(Duration::from_millis(1000));
        loop {
            interval.tick().await;

            // We can't use async in retain.
            let mut stale_peers = Vec::new();
            shared_state.peers.write().await.retain(|address, peer| {
                let is_peer_active = peer.last_psf_timestamp.elapsed() < PEER_REMOVE_TIMEOUT
                    || peer.last_mif_timestamp.elapsed() < PEER_REMOVE_TIMEOUT;

                if !is_peer_active {
                    stale_peers.push(*address);
                }

                is_peer_active
            });

            let mut ipv6_control_interface = shared_state.ipv6_control_interface.lock().await;
            for stale_peer_address in stale_peers {
                info!("Removing peer {stale_peer_address} due to inactivity.");
                ipv6_control_interface
                    .remove_peer_from_neighbor_table(stale_peer_address)
                    .await;
            }
        }
    }
    async fn wifi_in_eth_out_task(
        shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>,
        mut wifi_read_half: ReadHalf<WiFiDataInterface>,
        mut ethernet_write_half: WriteHalf<EthernetDataInterface>,
    ) {
        let mut wifi_buf = [0x00u8; 0x2000];
        loop {
            let read = wifi_read_half
                .read(&mut wifi_buf)
                .await
                .expect("Failed to receive packet from WiFi interface.");
            process_wifi_frame(&shared_state, &mut ethernet_write_half, &wifi_buf[..read]).await;
        }
    }
    async fn election_task(shared_state: Arc<SharedState<impl IPv6ControlInterface>>) {
        let mut election_timer = interval(Duration::from_secs(1));
        loop {
            election_timer.tick().await;
            let peers = shared_state.peers.read().await;
            let master_peer = peers.values().fold(None, |current_master_peer, peer| {
                if let Some(current_master_peer) = current_master_peer {
                    if is_peer_more_eligable_for_master(current_master_peer, peer) {
                        Some(peer)
                    } else {
                        Some(current_master_peer)
                    }
                } else {
                    Some(peer)
                }
            });
            let mut self_state = shared_state.self_state.write().await;
            if let Some(master_peer) = master_peer {
                self_state.sync_state.sync_to(master_peer.sync_state);
                if self_state.election_state.sync_master_address != master_peer.address {
                    info!("Adopting {} as master.", master_peer.address);
                }
                self_state.election_state.sync_master_address = master_peer.address;
                self_state.election_state.top_master_address =
                    master_peer.election_state.top_master_address;
            } else if !self_state.are_we_master() {
                self_state.set_master_to_self();
                info!("We are master now, due to lack of other peers. I feel so alone :(");
            }
        }
    }
    async fn channel_switch_task(
        shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>,
        mut wifi_control_interface: WiFiControlInterfaceInstance,
    ) {
        // We keep a local copy, as to not maintain constant read lock on the RwLock.
        let mut sync_state = shared_state.self_state.read().await.sync_state;
        let mut current_channel = 44;
        loop {
            select! {
                biased;
                _ = sleep(sync_state.time_to_next_slot()) => {
                    let new_channel = sync_state.current_channel().channel();
                    if current_channel != new_channel {
                        current_channel = new_channel;
                        
                        wifi_control_interface.set_channel(new_channel, match new_channel {
                            44 => ChannelWidth::TwentyMHz,
                            6 => ChannelWidth::TwentyMHz,
                            _ => todo!()
                        }).await;
                        trace!("Switched to channel {new_channel}.");
                    }
                },
                _ = shared_state.sync_change_notify.notified() => {
                    sync_state = shared_state.self_state.read().await.sync_state;
                },
            }
        }
    }
    pub async fn run(self, mac_address: MACAddress) {
        let Self {
            wifi_data_interface,
            mut wifi_control_interface,
            ethernet_data_interface,
            ipv6_control_interface,
        } = self;

        wifi_control_interface
            .set_channel(44, ChannelWidth::EightyMHZ)
            .await;

        let (wifi_read_half, wifi_write_half) = wifi_data_interface;
        let (ethernet_read_half, ethernet_write_half) = ethernet_data_interface;

        let shared_state = Arc::new(SharedState::new(ipv6_control_interface, mac_address));

        let _ = join!(
            spawn(Self::purge_stale_peers_task(shared_state.clone())),
            spawn(Self::wifi_in_eth_out_task(
                shared_state.clone(),
                wifi_read_half,
                ethernet_write_half
            )),
            spawn(Self::election_task(shared_state.clone())),
            spawn(Self::channel_switch_task(
                shared_state.clone(),
                wifi_control_interface
            ))
        );
    }
}