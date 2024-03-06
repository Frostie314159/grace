#![allow(unused)]
use log::LevelFilter;
use packet_core::PacketCore;

mod constants;
mod hal_impls;
mod hals;
mod llc;
mod packet_core;
mod peer;
mod state;
mod util;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Trace)
        .init();
    sudo::escalate_if_needed().unwrap();
    let mut packet_core =
        PacketCore::new("wlan1", [0x00, 0x80, 0x41, 0x13, 0x37, 0x42].into()).await;
    packet_core.run().await;
}
