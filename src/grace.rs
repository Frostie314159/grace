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

use std::{array, collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

use awdl_frame_parser::{
    action_frame::{AWDLActionFrameSubType, DefaultAWDLActionFrame},
    data_frame::AWDLDataFrame,
};
use circular_buffer::CircularBuffer;
use ethernet::{Ethernet2Frame, Ethernet2Header, OwnedEthernet2Frame};
use ieee80211::{
    common::TU,
    data_frame::{header::DataFrameHeader, DataFrame, DataFrameReadPayload},
    elements::rates::EncodedRate,
    mgmt_frame::{
        body::{action::ActionFrameBody, ManagementFrameBody},
        header::ManagementFrameHeader,
        ManagementFrame,
    },
    IEEE80211Frame, ToFrame,
};
use itertools::Itertools;
use log::{info, trace};
use mac_parser::MACAddress;
use rtap::{field_types::RadiotapField, frame::RadiotapFrame};
use scroll::{ctx::MeasureWith, Pread, Pwrite};
use tokio::{
    io::{unix::AsyncFd, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    join, select, spawn,
    sync::{mpsc, watch, Mutex, RwLock},
    time::{interval, sleep, timeout, MissedTickBehavior},
};

use crate::{
    constants::{AWDL_BSSID, DEFAULT_SLOT_DURATION},
    hals::{IPv6ControlInterface, WiFiControlInterface},
    llc::AWDLLLCFrame,
    peer::Peer,
    state::SelfState,
    sync::SyncState,
    util::APPLE_OUI,
};

const PEER_REMOVE_TIMEOUT: Duration = Duration::from_secs(5);

struct SharedState<IPv6ControlInterfaceInstance: IPv6ControlInterface> {
    peers: RwLock<HashMap<MACAddress, Peer>>,
    ipv6_control_interface: Mutex<IPv6ControlInterfaceInstance>,
    self_state: RwLock<SelfState>,
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
fn sort_frame_into_bucket(
    self_sync_state: &SyncState,
    other_sync_state: &SyncState,
    frame: OwnedEthernet2Frame,
    slot_buckets: &mut [CircularBuffer<8, OwnedEthernet2Frame>; 16],
) -> Option<()> {
    slot_buckets[self_sync_state
        .overlaping_slots(other_sync_state)
        .sorted_by(|a, b| slot_buckets[*a].len().cmp(&slot_buckets[*b].len()))
        .next()?]
    .push_back(frame);
    Some(())
}
fn build_awdl_data_frame(ethernet_frame: &OwnedEthernet2Frame, sequence_number: u16) -> Vec<u8> {
    let awdl_data_frame = AWDLDataFrame {
        ether_type: ethernet_frame.header.ether_type,
        sequence_number,
        payload: ethernet_frame.payload.as_slice(),
    };
    let llc_frame = AWDLLLCFrame {
        ssap: 0xaa,
        dsap: 0xaa,
        payload: awdl_data_frame,
    };
    let wifi_frame = DataFrame {
        header: DataFrameHeader {
            address_1: ethernet_frame.header.dst,
            address_2: ethernet_frame.header.src,
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

    frame_buf
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
    async fn election_task(
        shared_state: Arc<SharedState<impl IPv6ControlInterface>>,
        sync_state_tx: watch::Sender<SyncState>,
    ) {
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

                let _ = sync_state_tx.send(master_peer.sync_state);
            } else if !self_state.are_we_master() {
                self_state.set_master_to_self();
                info!("We are master now, due to lack of other peers. I feel so alone :(");
            }
        }
    }
    async fn channel_switch_task(
        shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>,
        mut wifi_control_interface: WiFiControlInterfaceInstance,
        mut sync_state_rx: watch::Receiver<SyncState>,
    ) {
        // We keep a local copy, as to not maintain constant read lock on the RwLock.
        let mut sync_state = shared_state.self_state.read().await.sync_state;
        let mut current_channel = 44;

        /* wifi_control_interface
        .set_channel(current_channel, ChannelWidth::EightyMHZ)
        .await; */

        loop {
            select! {
                /* _ = sleep(sync_state.remaining_slot_length()) => {
                    let new_channel = sync_state.current_channel().channel();
                    if current_channel != new_channel {
                        current_channel = new_channel;

                        wifi_control_interface.set_channel(new_channel, match new_channel {
                            44 => ChannelWidth::EightyMHZ,
                            6 => ChannelWidth::TwentyMHz,
                            _ => todo!()
                        }).await;
                        trace!("Switched to channel {new_channel}.");
                    }
                }, */
                _ = sync_state_rx.changed() => {
                    sync_state = sync_state_rx.borrow_and_update().clone();
                },
            }
        }
    }
    async fn eth_in_task(
        mut ethernet_read_half: ReadHalf<EthernetDataInterface>,
        wifi_packet_queue_tx: mpsc::Sender<OwnedEthernet2Frame>,
    ) {
        let mut buf = [0x00u8; 1512];
        loop {
            let read = ethernet_read_half
                .read(&mut buf)
                .await
                .expect("Failed to read from tap interface.");
            let Ok(ethernet_frame) = buf[..read].pread::<Ethernet2Frame>(0) else {
                continue;
            };
            let _ = wifi_packet_queue_tx
                .send(OwnedEthernet2Frame {
                    header: ethernet_frame.header,
                    payload: ethernet_frame.payload.to_vec(),
                })
                .await;
        }
    }
    async fn wifi_out_task(
        shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>,
        mut wifi_write_half: WriteHalf<WiFiDataInterface>,
        mut wifi_packet_queue_rx: mpsc::Receiver<OwnedEthernet2Frame>,
        mut sync_state_rx: watch::Receiver<SyncState>,
    ) {
        let mut sync_state = shared_state.self_state.read().await.sync_state;
        let mut psf_timer = interval(TU * 110);
        psf_timer.set_missed_tick_behavior(MissedTickBehavior::Burst);
        let mut slot_buckets =
            array::from_fn::<_, 16, _>(|_| CircularBuffer::<8, OwnedEthernet2Frame>::new());
        let mut frames_in_queue = 0;

        let mut sequence_number = 0u16;
        loop {
            select! {
                _ = psf_timer.tick() => {
                    let frame = shared_state.self_state.read().await.generate_awdl_af(AWDLActionFrameSubType::PSF);
                    let _ = wifi_write_half.write(frame.as_slice()).await;
                    trace!("Send PSF.");
                }
                    _ = sleep(sync_state.remaining_slot_length()), if frames_in_queue > 0 => {
                        let current_slot = sync_state.current_slot_in_chanseq();
                        if current_slot == 8 {
                            let frame = shared_state.self_state.read().await.generate_awdl_af(AWDLActionFrameSubType::MIF);
                            let _ = wifi_write_half.write(frame.as_slice()).await;
                            trace!("Send MIF.");
                        }
                        // Prevent to many frames from blocking the task.
                        let _ = timeout(DEFAULT_SLOT_DURATION - TU * 4, async {
                            while let Some(front) = slot_buckets[current_slot].front() {
                                let frame = build_awdl_data_frame(front, sequence_number);
                                let _ = wifi_write_half.write(frame.as_slice()).await;
                                sequence_number += 1;

                                let _ = slot_buckets[current_slot].pop_front();
                                frames_in_queue -= 1;
                            }
                        }).await;
                    }
                Some(ethernet_frame) = wifi_packet_queue_rx.recv() => {
                    let peers = shared_state.peers.read().await;
                    let Some(peer) = peers.get(&ethernet_frame.header.dst) else {
                        continue;
                    };
                    let other_sync_state = peer.sync_state.clone();
                    sort_frame_into_bucket(&sync_state, &other_sync_state, ethernet_frame, &mut slot_buckets);
                    frames_in_queue += 1;
                }
                _ = sync_state_rx.changed() => {
                    sync_state = *sync_state_rx.borrow_and_update();
                }
            }
        }
    }
    
    pub async fn run(self, mac_address: MACAddress) {
        let Self {
            wifi_data_interface,
            wifi_control_interface,
            ethernet_data_interface,
            ipv6_control_interface,
        } = self;

        let shared_state = Arc::new(SharedState::new(ipv6_control_interface, mac_address));

        let (wifi_read_half, wifi_write_half) = wifi_data_interface;
        let (ethernet_read_half, ethernet_write_half) = ethernet_data_interface;
        let (wifi_packet_queue_tx, wifi_packet_queue_rx) = mpsc::channel(0x20);
        let (sync_state_tx, sync_state_rx) =
            watch::channel(shared_state.self_state.read().await.sync_state);

        let _ = join!(
            spawn(Self::purge_stale_peers_task(shared_state.clone())),
            spawn(Self::wifi_in_eth_out_task(
                shared_state.clone(),
                wifi_read_half,
                ethernet_write_half
            )),
            spawn(Self::election_task(shared_state.clone(), sync_state_tx)),
            spawn(Self::channel_switch_task(
                shared_state.clone(),
                wifi_control_interface,
                sync_state_rx.clone()
            )),
            spawn(Self::eth_in_task(ethernet_read_half, wifi_packet_queue_tx)),
            spawn(Self::wifi_out_task(
                shared_state.clone(),
                wifi_write_half,
                wifi_packet_queue_rx,
                sync_state_rx
            ))
        );
    }
}
