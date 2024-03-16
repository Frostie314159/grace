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

use hals::{EthernetInterface, HostEthernetInterface, HostWiFiInterface, WiFiInterface};
//#![allow(unused)]
use grace::{Grace, TrafficMode};
use log::LevelFilter;
use mac_parser::MACAddress;
//use packet_core::PacketCore;

mod constants;
mod hal_impls;
mod hals;
mod llc;
//mod packet_core;
mod grace;
mod macros;
mod peer;
mod state;
mod sync;
mod util;

const MAC_ADDRESS: MACAddress = MACAddress::new([0x00, 0xc0, 0xca, 0xb3, 0xf1, 0xe8]);

//#[tokio::main(flavor = "current_thread")]
#[tokio::main]
async fn run() {
    let grace = Grace::new(
        HostWiFiInterface::new("wlan1").await.unwrap(),
        HostEthernetInterface::new(MAC_ADDRESS).unwrap(),
    );
    grace.run(MAC_ADDRESS, TrafficMode::BulkData).await;
}

// Setup code goes here.
fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Trace)
        .filter_module("neli", LevelFilter::Error)
        .init();
    sudo::escalate_if_needed().unwrap();
    run();
}
