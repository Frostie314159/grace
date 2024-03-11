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

use crate::hal_impls::{pcap_wifi::PcapWiFiInterface, *};
use cfg_if::cfg_if;
use core::future::Future;
use mac_parser::MACAddress;
use std::io::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

#[derive(Debug)]
pub enum EthernetInterfaceError<PlatformError> {
    NotPermitted,
    IOError(Error),
    PlatformSpecificError(PlatformError),
    Unknown,
}
pub trait IPv6ControlInterface: Sized + Send + Sync + 'static {
    fn add_peer_to_neighbor_table(&mut self, lladdr: MACAddress) -> impl Future + Send + Sync;
    fn remove_peer_from_neighbor_table(&mut self, lladdr: MACAddress) -> impl Future + Send + Sync;
}
pub trait EthernetInterface<PlatformError>
where
    Self: Sized + Send + Sync + 'static,
{
    type InternalIO: AsyncRead + AsyncWrite + Sized + Send + Sync + 'static;
    fn new(
        hardware_address: MACAddress,
    ) -> Result<
        (
            impl IPv6ControlInterface,
            ReadHalf<Self::InternalIO>,
            WriteHalf<Self::InternalIO>,
        ),
        EthernetInterfaceError<PlatformError>,
    >;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelWidth {
    TwentyMHz,
    FourtyMHzLower,
    FourtyMHzUpper,
    EightyMHZ,
    OneHundredAndSixtyMHz,
    ThreeHundredAndTwentyMHz,
}
#[derive(Debug)]
pub enum WiFiInterfaceError<PlatformError> {
    NoInterfaceWithThatName,
    InterfaceIsNotWireless,
    Other(&'static str),
    PlatformSpecificError(PlatformError),
}
pub trait WiFiControlInterface: Sized + Send + Sync + 'static {
    fn set_channel(
        &mut self,
        channel: u8,
        channel_width: ChannelWidth,
    ) -> impl Future + Send + Sync;
}
pub trait WiFiInterface<PlatformError>
where
    Self: Sized + Send + Sync + 'static,
{
    type InternalIO: AsyncRead + AsyncWrite + Sized + Send + Sync + 'static;
    fn new(
        interface_name: &str,
    ) -> impl Future<
        Output = Result<
            (
                impl WiFiControlInterface,
                ReadHalf<Self::InternalIO>,
                WriteHalf<Self::InternalIO>,
            ),
            WiFiInterfaceError<PlatformError>,
        >,
    > + Send;
}
cfg_if! {
    if #[cfg(feature = "linux")] {
        pub type HostEthernetInterface = linux::LinuxEthernetInterface;
        pub type HostWiFiInterface = PcapWiFiInterface;
    } else {
        compile_error!("A host target is required.");
    }
}
