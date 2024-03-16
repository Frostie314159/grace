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

use std::net::Ipv6Addr;

use mac_parser::MACAddress;

pub const APPLE_OUI: [u8; 3] = [0x00, 0x17, 0xf2];

pub const fn ipv6_addr_from_hw_address(hardware_address: MACAddress) -> Ipv6Addr {
    let hardware_address = hardware_address.0;
    Ipv6Addr::new(
        0xfe80,
        0x0000,
        0x0000,
        0x0000,
        u16::from_be_bytes([hardware_address[0] ^ 0x2, hardware_address[1]]),
        u16::from_be_bytes([hardware_address[2], 0xff]),
        u16::from_be_bytes([0xfe, hardware_address[3]]),
        u16::from_be_bytes([hardware_address[4], hardware_address[5]]),
    )
}
