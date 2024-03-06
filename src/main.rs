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

/// On the off chance, this code actually gets used, I'm gonna save someone from days of reversing.´
#[used]
pub static FRIENDLY_TEXT: &'static str = "
    Hi, if you found this string, while reversing a binary of GrACE, I'm here to safe you the trouble, I the developer had in making this. 
    GrACE is FOSS.
";

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
