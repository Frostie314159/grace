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
    action_frame::{AWDLActionFrameSubType, DefaultAWDLActionFrame},
    common::AWDLDnsCompression,
    data_frame::AWDLDataFrame,
};
use ethernet::{Ethernet2Frame, Ethernet2Header};
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
use log::{info, trace};
use mac_parser::MACAddress;
use rcap::AsyncCapture;
use rtap::{field_types::RadiotapField, frame::RadiotapFrame};
use scroll::{ctx::MeasureWith, Pread, Pwrite};
use std::{
    collections::HashMap,
    marker::PhantomData,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    join,
    net::TcpListener,
    select, spawn,
    sync::{watch, Mutex, RwLock},
    time::{interval, sleep},
};

use crate::{
    constants::AWDL_BSSID,
    hals::{ChannelWidth, IPv6ControlInterface, WiFiControlInterface},
    llc::AWDLLLCFrame,
    peer::Peer,
    state::{ElectionState, SelfState},
    sync::SyncState,
    util::{ipv6_addr_from_hw_address, APPLE_OUI},
};

const PEER_REMOVE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct SharedState<IPv6ControlInterfaceInstance: IPv6ControlInterface> {
    pub peers: RwLock<HashMap<MACAddress, Peer>>,
    pub ipv6_control_interface: Mutex<IPv6ControlInterfaceInstance>,
    pub self_state: RwLock<SelfState>,
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
/// Convenience method, so we avoid cloning the iterator.
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
/// Creates an ethernet frame from the data frame payload.
/// This destructures the LLC and AWDL Data header.
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
/// Equivalent to `IO80211Family::actionFrameInput`.
async fn process_awdl_action_frame(
    shared_state: &Arc<SharedState<impl IPv6ControlInterface>>,
    header: ManagementFrameHeader,
    payload: &[u8],
) {
    let Ok(awdl_action_frame) = payload.pread::<DefaultAWDLActionFrame>(0) else {
        return;
    };
    // Acquire the lock once, since we'll always write to it.
    let mut peer_list = shared_state.peers.write().await;

    if let Some(peer) = peer_list.get_mut(&header.transmitter_address) {
        // Update sync state etc.
        peer.update_with_af(awdl_action_frame).await;
    } else {
        // Initialize the peer.
        let Some(peer) = Peer::new_with_af(header, awdl_action_frame) else {
            return;
        };
        info!("Adding peer {} to peer list.", header.transmitter_address);
        peer_list.insert(header.transmitter_address, peer);

        // Add it to the neighbor table so we can communicate with it.
        shared_state
            .ipv6_control_interface
            .lock()
            .await
            .add_peer_to_neighbor_table(header.transmitter_address)
            .await;
    }
}
/// All wifi frames go in here.
async fn process_wifi_frame(
    shared_state: &Arc<SharedState<impl IPv6ControlInterface>>,
    ethernet_write_half: &mut WriteHalf<impl AsyncWrite + Send + Sync + 'static>,
    buf: &[u8],
) {
    // Take the radiotap header apart.
    let Ok(radiotap_frame) = buf.pread::<RadiotapFrame>(0) else {
        return;
    };
    // Currently unused.
    let (_rssi,) = extract_fields_from_radiotap_iter(&mut radiotap_frame.get_field_iter());
    // This will already decode it into either a data frame or an action frame.
    let Ok(wifi_frame) = radiotap_frame.payload.pread::<IEEE80211Frame>(0) else {
        return;
    };
    let fcf_flags = wifi_frame.get_fcf().flags();

    // AWDL frames are always neither to nor from DS, since it's Ad-Hoc.
    if fcf_flags.to_ds() || fcf_flags.from_ds() {
        return;
    }

    match wifi_frame {
        // We only care about vendor specific AFs with apple's OUI.
        // BSSID check is done in [process_awdl_action_frame].
        IEEE80211Frame::Management(ManagementFrame {
            header,
            body:
                ManagementFrameBody::Action(ActionFrameBody::VendorSpecific {
                    oui: APPLE_OUI,
                    payload,
                }),
        }) => process_awdl_action_frame(shared_state, header, payload).await,
        IEEE80211Frame::Data(data_frame) => {
            // BSSID check is done here.
            if data_frame.header.bssid().copied() == Some(AWDL_BSSID) {
                process_awdl_data_frame(ethernet_write_half, data_frame).await;
            }
        }
        // Other frames are irrelevant to us.
        _ => {}
    }
}
/// Our election algorithm.
fn is_peer_more_eligable_for_master(lhs: &ElectionState, rhs: &ElectionState) -> bool {
    // TODO: This isn't completely right.
    lhs.self_metric < rhs.self_metric
}
// TODO: Make this not allocate.
/// Assemble and AWDL data frame from an ethernet header and a sequence number.
fn build_awdl_data_frame(ethernet_frame: Ethernet2Frame, sequence_number: u16) -> Vec<u8> {
    // We assemble them in reverse order, due to how the RW works.
    let awdl_data_frame = AWDLDataFrame {
        ether_type: ethernet_frame.header.ether_type,
        sequence_number,
        payload: ethernet_frame.payload,
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
    // This is just a default radiotap header, with FCS at the end and a fixed rate.
    frame_buf[2] = 10;
    frame_buf[4] = 0x06;
    frame_buf[8] = 0x10;
    frame_buf[9] = EncodedRate::from_rate_in_kbps(54000, false).into_bits();

    frame_buf
}
/// Asynchronously await the slot and transmit the data frame.
async fn wait_for_slot_and_transmit(
    capture: &Arc<AsyncCapture>,
    self_sync_state: &SyncState,
    slot: usize,
    ethernet_frame: Ethernet2Frame<'_>,
    sequence_number: &mut u16,
) {
    let frame = build_awdl_data_frame(ethernet_frame, *sequence_number);

    // TODO: This is currently a bit ugly.
    *sequence_number += 1;

    // SyncState tells us the duration we have to sleep.
    sleep(self_sync_state.time_to_slot_with_gi(slot)).await;

    let _ = capture.send(&frame).await;
    info!("Transmitted frame.");
}

pub struct Grace<
    WiFiControlInterfaceInstance: WiFiControlInterface,
    EthernetDataInterface: AsyncRead + AsyncWrite,
    IPv6ControlInterfaceInstance: IPv6ControlInterface,
> {
    wifi_data_interface: AsyncCapture,
    wifi_control_interface: WiFiControlInterfaceInstance,
    ethernet_data_interface: (
        ReadHalf<EthernetDataInterface>,
        WriteHalf<EthernetDataInterface>,
    ),
    ipv6_control_interface: IPv6ControlInterfaceInstance,
}
impl<
        WiFiControlInterfaceInstance: WiFiControlInterface + 'static,
        EthernetDataInterface: AsyncRead + AsyncWrite + Send + Sync + 'static,
        IPv6ControlInterfaceInstance: IPv6ControlInterface + 'static,
    > Grace<WiFiControlInterfaceInstance, EthernetDataInterface, IPv6ControlInterfaceInstance>
{
    #[inline]
    pub fn new(
        wifi_interface: (WiFiControlInterfaceInstance, AsyncCapture),
        ethernet_interface: (
            IPv6ControlInterfaceInstance,
            ReadHalf<EthernetDataInterface>,
            WriteHalf<EthernetDataInterface>,
        ),
    ) -> Self {
        Self {
            wifi_data_interface: wifi_interface.1,
            wifi_control_interface: wifi_interface.0,
            ethernet_data_interface: (ethernet_interface.1, ethernet_interface.2),
            ipv6_control_interface: ethernet_interface.0,
        }
    }
    async fn purge_stale_peers_task(shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>) {
        // We check every 0.5s if peers have become stale. Should be sufficient.
        // Making this duration smaller will cause lock contention.
        let mut interval = interval(Duration::from_millis(500));
        loop {
            interval.tick().await;

            // We can't use async in retain.
            let mut stale_peers = Vec::new();
            shared_state.peers.write().await.retain(|address, peer| {
                // If either a PSF or an MIF was received in the [PEER_REMOVE_TIMEOUT] the peer is fine.
                let is_peer_active = peer.last_psf_timestamp.elapsed() < PEER_REMOVE_TIMEOUT
                    || peer.last_mif_timestamp.elapsed() < PEER_REMOVE_TIMEOUT;
                // If it isnt... Bye bye
                if !is_peer_active {
                    stale_peers.push(*address);
                }

                is_peer_active
            });

            let mut ipv6_control_interface = shared_state.ipv6_control_interface.lock().await;
            // Remove them from the neighbor table.
            for stale_peer_address in stale_peers {
                info!("Removing peer {stale_peer_address} due to inactivity.");
                ipv6_control_interface
                    .remove_peer_from_neighbor_table(stale_peer_address)
                    .await;
            }
        }
    }
    // Receive frames from the monitor interface, process them and send MSDUs up to the TAP interface.
    async fn wifi_in_eth_out_task(
        shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>,
        capture: Arc<AsyncCapture>,
        mut ethernet_write_half: WriteHalf<EthernetDataInterface>,
    ) {
        let mut wifi_buf = [0x00u8; 1512];
        loop {
            let read = capture
                .recv(wifi_buf.as_mut_slice())
                .await
                .expect("Failed to receive packet.");
            process_wifi_frame(&shared_state, &mut ethernet_write_half, &wifi_buf[..read]).await;
        }
    }
    // We elect our master here.
    async fn election_task(
        shared_state: Arc<SharedState<impl IPv6ControlInterface>>,
        sync_state_tx: watch::Sender<SyncState>,
    ) {
        let mut election_timer = interval(Duration::from_millis(300));
        loop {
            election_timer.tick().await;
            let peers = shared_state.peers.read().await;

            // Look for the peer with the highest metric.
            let master_peer = peers
                .values()
                .fold(None::<&Peer>, |current_master_peer, peer| {
                    if let Some(current_master_peer) = current_master_peer {
                        if is_peer_more_eligable_for_master(
                            &current_master_peer.election_state,
                            &peer.election_state,
                        ) {
                            Some(peer)
                        } else {
                            Some(current_master_peer)
                        }
                    } else {
                        Some(peer)
                    }
                });
            let mut self_state = shared_state.self_state.write().await;
            // If there is a winner...
            if let Some(master_peer) = master_peer {
                // Check if we are more eligible
                if is_peer_more_eligable_for_master(
                    &master_peer.election_state,
                    &self_state.election_state,
                ) {
                    // Only set master to self if we aren't already master.
                    if !self_state.are_we_master() {
                        self_state.set_master_to_self();
                        let _ = sync_state_tx.send(self_state.sync_state);

                        info!("We are master now. Victory!");
                    }
                // Otherwise adopt it as master.
                } else {
                    self_state.sync_state.sync_to(master_peer.sync_state);

                    // If we've already adopted the other peer as master, there is no need to log it again.
                    if self_state.election_state.sync_master_address != master_peer.address {
                        info!("Adopting {} as master.", master_peer.address);
                    }

                    // Doing this anyway.
                    self_state.election_state.sync_master_address = master_peer.address;
                    self_state.election_state.top_master_address =
                        master_peer.election_state.top_master_address;

                    // Announce the sync change.
                    let _ = sync_state_tx.send(self_state.sync_state);
                }
            // If there are no other peers we'll have to do it ourselves.
            } else if !self_state.are_we_master() {
                self_state.set_master_to_self();

                // Announce the sync change.
                let _ = sync_state_tx.send(self_state.sync_state);
                info!("We are master now, due to lack of other peers. I feel so alone :(");
            }
        }
    }
    /// This switches between channels.
    async fn channel_switch_task(
        shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>,
        mut wifi_control_interface: WiFiControlInterfaceInstance,
        mut sync_state_rx: watch::Receiver<SyncState>,
    ) {
        // We keep a local copy, as to not maintain constant read lock on the RwLock.
        let mut sync_state = shared_state.self_state.read().await.sync_state;

        let mut current_channel = 6;
        loop {
            select! {
                _ = sleep(sync_state.remaining_slot_length()) => {
                    let new_channel = sync_state.current_channel().channel();
                    // If the channels diverge, switch.
                    if current_channel != new_channel {
                        current_channel = new_channel;

                        wifi_control_interface.set_channel(new_channel, match new_channel {
                            44 => ChannelWidth::EightyMHZ,
                            6 => ChannelWidth::TwentyMHz,
                            _ => ChannelWidth::FourtyMHzUpper
                        }).await;
                        trace!("Switched to channel {new_channel}.");
                    }
                },
                // Receive sync changes.
                _ = sync_state_rx.changed() => {
                    sync_state = *sync_state_rx.borrow_and_update();
                },
            }
        }
    }
    // Ethernet comes in, WiFi/AWDL goes out.
    async fn eth_in_wifi_data_out_task(
        shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>,
        capture: Arc<AsyncCapture>,
        mut ethernet_read_half: ReadHalf<EthernetDataInterface>,
        mut sync_state_rx: watch::Receiver<SyncState>,
    ) {
        let mut sync_state = shared_state.self_state.read().await.sync_state;

        let mut sequence_number = 0u16;
        // Static buffer for ethernet reception.
        let mut ethernet_buf = [0x00u8; 1500];
        loop {
            select! {
                // Receive from the ethernet interface.
                Ok(read) = ethernet_read_half.read(ethernet_buf.as_mut_slice()) => {
                    let Ok(ethernet_frame) = ethernet_buf[..read].pread::<Ethernet2Frame>(0) else {
                        continue;
                    };
                    // Multicast frames always go out on slot 0 or 10 and unicast slots depend on the peer.
                    let slot = if ethernet_frame.header.dst.is_multicast() {
                        if sync_state.distance_to_slot(0) < sync_state.distance_to_slot(10) {
                            0
                        } else {
                            10
                        }
                    } else {
                        // Find the nearest overlapping slot.
                        let peers = shared_state.peers.read().await;
                        let Some(peer) = peers.get(&ethernet_frame.header.dst) else {
                            continue;
                        };
                        let other_sync_state = peer.sync_state;
                        let Some(slot) = sync_state.overlaping_slots(&other_sync_state).min_by_key(|slot| sync_state.time_to_slot_with_gi(*slot)) else {
                            info!("Unable to transmit frame to {} due to no overlapping slots.", ethernet_frame.header.dst);
                            continue;
                        };
                        slot
                    };
                    // Wait and transmit.
                    wait_for_slot_and_transmit(&capture, &sync_state, slot, ethernet_frame, &mut sequence_number).await;
                }
                // Receive sync changes.
                _ = sync_state_rx.changed() => {
                    sync_state = *sync_state_rx.borrow_and_update();
                }
            }
        }
    }
    // Transmits PSFs and MIFs.
    async fn wifi_control_out_task(
        shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>,
        capture: Arc<AsyncCapture>,
        mut sync_state_rx: watch::Receiver<SyncState>,
    ) {
        let mut sync_state = shared_state.self_state.read().await.sync_state;
        // This is the default PSF interval.
        let mut psf_timer = interval(TU * 110);
        loop {
            select! {
                // Wait for the next tick.
                _ = psf_timer.tick() => {
                    let frame = shared_state.self_state.read().await.generate_awdl_af(AWDLActionFrameSubType::PSF);
                    let _ = capture.send(frame.as_slice()).await;
                    trace!("Send PSF.");
                }
                // Wait for next EAW.
                _ = sleep(sync_state.time_to_next_slot_with_gi()) => {
                    let frame = shared_state.self_state.read().await.generate_awdl_af(AWDLActionFrameSubType::MIF);
                    let _ = capture.send(frame.as_slice()).await;
                    trace!("Send MIF.");
                }
                // Receive sync changes.
                _ = sync_state_rx.changed() => {
                    sync_state = *sync_state_rx.borrow_and_update();
                }
            }
        }
    }
    /// This allows connecting to us on port 1337 on localhost and get a comma seperated list of all AirDrop peers every second.
    async fn service_discovery_task(shared_state: Arc<SharedState<IPv6ControlInterfaceInstance>>) {
        let tcp_listener = TcpListener::bind("[::]:1337")
            .await
            .expect("Failed to bind to address.");
        let mut clients: HashMap<std::net::SocketAddr, tokio::net::TcpStream> = HashMap::new();
        let mut update_interval = interval(Duration::from_secs(1));
        loop {
            select! {
                // Send the list every second.
                _ = update_interval.tick() => {
                    let peers = shared_state.peers.read().await;
                    // Generate the service string.
                    let service_string = peers.iter().fold(String::new(), |acc, (address, peer)| {
                        if let Some(ipv6_address) = peer.services.iter().find_map(|service| {
                            if service.domain == AWDLDnsCompression::AirDropTcpLocal {
                                Some(ipv6_addr_from_hw_address(*address).to_string())
                            } else {
                                None
                            }
                        }) {
                            acc + &ipv6_address + ","
                        }else {
                            acc
                        }

                    });
                    // If we have a trailing comma, remove it.
                    let service_string = service_string.strip_suffix(",").unwrap_or_default();
                    for (_, client) in clients.iter_mut() {
                        let Ok(_) = client.write(service_string.as_bytes()).await else {
                            continue;
                        };
                    }
                }
                // Accept new connections.
                client = tcp_listener.accept() => {
                    let client = client.unwrap();
                    clients.insert(client.1, client.0);
                }
            }
        }
    }
    // Execute grace.
    pub async fn run(self, mac_address: MACAddress) {
        let Self {
            wifi_data_interface,
            wifi_control_interface,
            ethernet_data_interface,
            ipv6_control_interface,
        } = self;

        let shared_state = Arc::new(SharedState::new(ipv6_control_interface, mac_address));

        let (ethernet_read_half, ethernet_write_half) = ethernet_data_interface;
        let (sync_state_tx, sync_state_rx) =
            watch::channel(shared_state.self_state.read().await.sync_state);

        // Setup the capture.
        let capture = Arc::new(wifi_data_interface);

        // Spawn the tasks.
        let _ = join!(
            spawn(Self::purge_stale_peers_task(shared_state.clone())),
            spawn(Self::wifi_in_eth_out_task(
                shared_state.clone(),
                capture.clone(),
                ethernet_write_half
            )),
            spawn(Self::election_task(shared_state.clone(), sync_state_tx)),
            spawn(Self::channel_switch_task(
                shared_state.clone(),
                wifi_control_interface,
                sync_state_rx.clone()
            )),
            spawn(Self::eth_in_wifi_data_out_task(
                shared_state.clone(),
                capture.clone(),
                ethernet_read_half,
                sync_state_rx.clone()
            )),
            spawn(Self::wifi_control_out_task(
                shared_state.clone(),
                capture.clone(),
                sync_state_rx
            )),
            spawn(Self::service_discovery_task(shared_state.clone()))
        );
    }
}
