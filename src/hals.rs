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
