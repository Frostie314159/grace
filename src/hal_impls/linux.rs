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

use std::ffi::CStr;

use mac_parser::MACAddress;
use neli::{
    consts::nl::{NlmF, Nlmsg},
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, Nlattr, NlattrBuilder, NoUserHeader},
    nl::NlPayload,
    router::asynchronous::NlRouter,
    types::Buffer,
};
use neli_wifi::{AsyncSocket, Nl80211Attr, Nl80211Cmd, NL_80211_GENL_NAME, NL_80211_GENL_VERSION};
use tidy_tuntap::{error::Error as TunTapError, AsyncDevice, InterfaceType, Tap};

use crate::{
    hals::{
        ChannelWidth, EthernetInterface, EthernetInterfaceError, IPv6ControlInterface,
        WiFiControlInterface,
    },
    util::ipv6_addr_from_hw_address,
};

use tokio::{
    io::{split, ReadHalf, WriteHalf},
    process::Command,
};

pub struct LinuxIPv6ControlInteface;
impl IPv6ControlInterface for LinuxIPv6ControlInteface {
    async fn add_peer_to_neighbor_table(&mut self, lladdr: MACAddress) {
        let _ = Command::new("ip")
            .args([
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
            .wait()
            .await;
    }
    async fn remove_peer_from_neighbor_table(&mut self, lladdr: MACAddress) {
        let _ = Command::new("ip")
            .args([
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
            .wait()
            .await;
    }
}

pub struct LinuxEthernetInterface;
impl EthernetInterface<TunTapError> for LinuxEthernetInterface {
    type InternalIO = AsyncDevice<Tap>;
    fn new(
        hardware_address: MACAddress,
    ) -> Result<
        (
            impl IPv6ControlInterface,
            ReadHalf<Self::InternalIO>,
            WriteHalf<Self::InternalIO>,
        ),
        EthernetInterfaceError<TunTapError>,
    > {
        let tap =
            Tap::new_async("awdl0", false).map_err(|_| EthernetInterfaceError::NotPermitted)?;
        tap.set_hwaddr(hardware_address.0).unwrap();
        /* tap.set_ipv6_addr(ipv6_addr_from_hw_address(hardware_address))
        .unwrap(); */
        tap.bring_up().unwrap();
        tap.set_mtu(1450).unwrap();
        let (read_half, write_half) = split(tap);
        Ok((LinuxIPv6ControlInteface, read_half, write_half))
    }
}
pub struct LinuxWiFiControlInterface {
    router: NlRouter,
    nl80211_family_id: u16,
    interface_index: i32,
}
impl LinuxWiFiControlInterface {
    pub async fn new(wifi_device: impl AsRef<str>) -> Self {
        let mut async_socket = AsyncSocket::connect()
            .await
            .expect("Failed to initialize neli async socket.");
        let interface_index = async_socket
            .get_interfaces_info()
            .await
            .unwrap()
            .into_iter()
            .find_map(|interface| {
                if let Some(interface_name) = interface.name {
                    if CStr::from_bytes_with_nul(&interface_name)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        == wifi_device.as_ref()
                    {
                        Some(interface.index.unwrap())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .expect("Failed to find interface index.");
        let router: NlRouter = async_socket.into();

        let nl80211_family_id = router
            .resolve_genl_family(NL_80211_GENL_NAME)
            .await
            .expect("Failed to resolve genl family.");

        Self {
            router,
            nl80211_family_id,
            interface_index,
        }
    }
    fn get_wifi_interface_attribute(&self) -> Nlattr<Nl80211Attr, Buffer> {
        // TODO: Neli is currently extremly ugly.
        Self::attribute_with_payload(Nl80211Attr::AttrIfindex, self.interface_index as u32)
    }
    fn channel_to_center_frequency(channel: usize) -> Option<usize> {
        // I hate channel numbers.
        match channel {
            1..=13 => Some(2412 + 5 * (channel - 1)),
            14 => Some(2484),
            32..=68 | 96..=144 | 149..=177 => Some(5160 + 5 * (channel - 32)),
            _ => None,
        }
    }
    fn convert_channel_width(channel_width: ChannelWidth) -> u32 {
        match channel_width {
            ChannelWidth::TwentyMHz => 1,
            ChannelWidth::FourtyMHzLower | ChannelWidth::FourtyMHzUpper => 2,
            ChannelWidth::EightyMHZ => 3,
            ChannelWidth::OneHundredAndSixtyMHz => 5,
            _ => todo!(),
        }
    }
    fn calculate_parameters_for_channel(
        channel: usize,
        channel_width: ChannelWidth,
    ) -> Option<(usize, Option<usize>)> {
        match channel_width {
            ChannelWidth::TwentyMHz => Some((Self::channel_to_center_frequency(channel)?, None)),
            ChannelWidth::FourtyMHzLower => Some((
                Self::channel_to_center_frequency(channel)?,
                Self::channel_to_center_frequency(channel - 4),
            )),
            ChannelWidth::FourtyMHzUpper => Some((
                Self::channel_to_center_frequency(channel)?,
                Self::channel_to_center_frequency(channel + 4),
            )),
            ChannelWidth::EightyMHZ => match channel {
                36..=48 => Some((5200, Some(5210))),
                52..=64 => Some((5290, Some(5280))),
                100..=112 => Some((5530, Some(5520))),
                116..=128 => Some((5610, Some(5600))),
                132..=144 => Some((5690, Some(5680))),
                _ => None,
            },
            _ => todo!(),
        }
    }
    fn attribute_with_payload(attribute: Nl80211Attr, payload: u32) -> Nlattr<Nl80211Attr, Buffer> {
        NlattrBuilder::default()
            .nla_type(
                AttrTypeBuilder::default()
                    .nla_nested(false)
                    .nla_network_order(false)
                    .nla_type(attribute)
                    .build()
                    .unwrap(),
            )
            .nla_payload(payload)
            .build()
            .unwrap()
    }
}
impl WiFiControlInterface for LinuxWiFiControlInterface {
    async fn set_channel(&mut self, channel: u8, channel_width: ChannelWidth) {
        let (center_frequency, support_frequency) =
            Self::calculate_parameters_for_channel(channel as usize, channel_width).unwrap_or_else(
                || panic!("Invalid channel config: channel {channel} width: {channel_width:?}"),
            );
        /* let center_frequency = 2437;
        let support_frequency = None::<usize>;
        let channel_width = ChannelWidth::TwentyMHz; */
        let mut attributes = vec![
            self.get_wifi_interface_attribute(),
            Self::attribute_with_payload(Nl80211Attr::AttrWiphyFreq, center_frequency as u32),
            Self::attribute_with_payload(
                Nl80211Attr::AttrChannelWidth,
                Self::convert_channel_width(channel_width),
            ),
        ];
        if let Some(support_frequency) = support_frequency {
            attributes.push(Self::attribute_with_payload(
                Nl80211Attr::AttrCenterFreq1,
                support_frequency as u32,
            ));
        }
        let genl_msg_hdr = GenlmsghdrBuilder::<Nl80211Cmd, Nl80211Attr, NoUserHeader>::default()
            .cmd(Nl80211Cmd::CmdSetChannel)
            .attrs(attributes.into_iter().collect())
            .version(NL_80211_GENL_VERSION)
            .build()
            .unwrap();
        self.router
            .send::<_, _, Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr, NoUserHeader>>(
                self.nl80211_family_id,
                NlmF::empty(),
                NlPayload::Payload(genl_msg_hdr),
            )
            .await
            .expect("Failed to set channel.");
    }
}
