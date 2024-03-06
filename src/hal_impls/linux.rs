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
