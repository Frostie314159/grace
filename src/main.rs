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

#![allow(refining_impl_trait)]

use hals::{EthernetInterface, HostEthernetInterface, HostWiFiInterface, WiFiInterface};
use grace::Grace;
use log::LevelFilter;
use mac_parser::MACAddress;

mod constants;
mod hal_impls;
mod hals;
mod llc;
mod grace;
mod macros;
mod peer;
mod service;
mod state;
mod sync;
mod util;

const MAC_ADDRESS: MACAddress = MACAddress::new([0x00, 0xc0, 0xca, 0xb3, 0xf1, 0xe8]);

#[tokio::main]
async fn run() {
    let grace = Grace::new(
        HostWiFiInterface::new("wlan1").await.unwrap(),
        HostEthernetInterface::new(MAC_ADDRESS).unwrap(),
    );
    grace.run(MAC_ADDRESS).await;
}

// Setup code goes here.
fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .filter_module("neli", LevelFilter::Error)
        .init();
    sudo::escalate_if_needed().unwrap();
    run();
}
