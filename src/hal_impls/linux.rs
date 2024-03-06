use std::{net::Ipv6Addr, process::Command};

use mac_parser::MACAddress;
use tidy_tuntap::{error::Error as TunTapError, AsyncDevice, InterfaceType, Tap};

use crate::{
    hals::{EthernetInterface, EthernetInterfaceError},
    util::ipv6_addr_from_hw_address,
};

use tokio::io::AsyncReadExt;

pub struct LinuxEthernetInterface {
    tap: AsyncDevice<Tap>,
}
impl EthernetInterface<TunTapError> for LinuxEthernetInterface {
    fn new(hardware_address: MACAddress) -> Result<Self, EthernetInterfaceError<TunTapError>> {
        let tap =
            Tap::new_async("awdl0", false).map_err(|_| EthernetInterfaceError::NotPermitted)?;
        tap.set_hwaddr(hardware_address.0).unwrap();
        tap.set_ipv6_addr(ipv6_addr_from_hw_address(hardware_address))
            .unwrap();
        tap.bring_up().unwrap();
        tap.set_mtu(1450).unwrap();
        Ok(Self { tap })
    }
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, EthernetInterfaceError<TunTapError>> {
        Ok(self.tap.read(buf).await.unwrap())
    }
    async fn send(&mut self, buf: &[u8]) -> Result<usize, EthernetInterfaceError<TunTapError>> {
        self.tap
            .send(buf)
            .await
            .map_err(EthernetInterfaceError::PlatformSpecificError)
    }
    fn add_peer_to_neighbor_table(&mut self, lladdr: MACAddress) {
        Command::new("ip")
            .args(&[
                "neigh",
                "add",
                ipv6_addr_from_hw_address(lladdr).to_string().as_str(),
                "lladdr",
                lladdr.to_string().as_str(),
                "dev",
                "awdl0",
            ])
            .spawn()
            .expect("Failed to run ip command!")
            .wait();
    }
    fn remove_peer_from_neighbor_table(&mut self, lladdr: MACAddress) {
        Command::new("ip")
            .args(&[
                "neigh",
                "delete",
                ipv6_addr_from_hw_address(lladdr).to_string().as_str(),
                "lladdr",
                lladdr.to_string().as_str(),
                "dev",
                "awdl0",
            ])
            .spawn()
            .expect("Failed to run ip command!")
            .wait();
    }
}
