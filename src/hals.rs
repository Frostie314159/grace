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

use crate::hal_impls::{pcap::PcapWiFiInterface, *};
use cfg_if::cfg_if;
use core::future::Future;
use mac_parser::MACAddress;
use std::{io::Error, net::Ipv6Addr};

#[derive(Debug)]
pub enum EthernetInterfaceError<PlatformError> {
    NotPermitted,
    IOError(Error),
    PlatformSpecificError(PlatformError),
    Unknown,
}
pub trait EthernetInterface<PlatformError>
where
    Self: Sized,
{
    fn new(hardware_address: MACAddress) -> Result<Self, EthernetInterfaceError<PlatformError>>;
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<usize, EthernetInterfaceError<PlatformError>>> + Send;
    fn send(
        &mut self,
        buf: &[u8],
    ) -> impl Future<Output = Result<usize, EthernetInterfaceError<PlatformError>>> + Send;
    fn add_peer_to_neighbor_table(&mut self, lladdr: MACAddress);
    fn remove_peer_from_neighbor_table(&mut self, lladdr: MACAddress);
}
pub enum ChannelWidth {
    TwentyMHz,
    FourtyMHz,
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
pub trait WiFiInterface<PlatformError>
where
    Self: Sized,
{
    fn new(interface_name: &str) -> Result<Self, WiFiInterfaceError<PlatformError>>;
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<usize, WiFiInterfaceError<PlatformError>>> + Send;
    fn send(
        &mut self,
        bytes: &[u8],
    ) -> impl Future<Output = Result<usize, WiFiInterfaceError<PlatformError>>> + Send;
    fn is_5ghz_supported(&self) -> bool;
    fn get_highest_channel_width(&self) -> ChannelWidth;
}
cfg_if! {
    if #[cfg(feature = "linux")] {
        pub type HostEthernetInterface = linux::LinuxEthernetInterface;
        pub type HostWiFiInterface = PcapWiFiInterface;
    } else {
        compile_error!("A host target is required.");
    }
}
