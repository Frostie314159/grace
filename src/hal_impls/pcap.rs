use std::{future::poll_fn, io::ErrorKind, task::Poll};

use futures::{ready, Future};
use pcap::{Active, Capture, Device, Direction, Linktype, Packet};
use tokio::io::{unix::AsyncFd, Interest};

use crate::hals::{ChannelWidth, WiFiInterface, WiFiInterfaceError};

pub struct PcapWiFiInterface {
    capture: AsyncFd<Capture<Active>>,
}
impl WiFiInterface<pcap::Error> for PcapWiFiInterface {
    fn new(interface_name: &str) -> Result<Self, WiFiInterfaceError<pcap::Error>> {
        let device = Device::list()
            .map_err(WiFiInterfaceError::PlatformSpecificError)?
            .into_iter()
            .find(|device| device.name == interface_name)
            .ok_or(WiFiInterfaceError::NoInterfaceWithThatName)?;
        if !device.flags.is_wireless() {
            return Err(WiFiInterfaceError::InterfaceIsNotWireless);
        }
        let mut capture = Capture::from_device(device)
            .map_err(WiFiInterfaceError::PlatformSpecificError)?
            .buffer_size(0xffff)
            .immediate_mode(true)
            .promisc(true)
            .open()
            .map_err(WiFiInterfaceError::PlatformSpecificError)?;
        capture
            .direction(Direction::InOut)
            .map_err(WiFiInterfaceError::PlatformSpecificError)?;
        capture
            .set_datalink(Linktype::IEEE802_11_RADIOTAP)
            .map_err(WiFiInterfaceError::PlatformSpecificError)?;
        Ok(Self {
            capture: AsyncFd::new(capture).unwrap(),
        })
    }
    /* async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, WiFiInterfaceError<pcap::Error>> {
        self.capture
            .async_io_mut(Interest::READABLE, |capture| {
                Ok(capture
                    .next_packet()
                    .map(|packet| {
                        buf[..packet.data.len()].copy_from_slice(packet.data);
                        packet.data.len()
                    })
                    .map_err(WiFiInterfaceError::PlatformSpecificError))
            })
            .await
            .unwrap()
    } */
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = Result<usize, WiFiInterfaceError<pcap::Error>>> + Send {
        poll_fn(|cx| loop {
            let mut guard = ready!(self.capture.poll_read_ready_mut(cx))
                .map_err(|_| WiFiInterfaceError::Other("IO Error"))?;
            match guard.try_io(|inner| {
                let Packet { data, .. } = inner
                    .get_mut()
                    .next_packet()
                    .map_err(|_| std::io::Error::new(ErrorKind::UnexpectedEof, ""))?;
                buf[..data.len()].copy_from_slice(data);
                Ok(data.len())
            }) {
                Ok(result) => {
                    return Poll::Ready(Ok(result.map_err(|_| WiFiInterfaceError::Other(""))?));
                }
                Err(_would_block) => continue,
            }
        })
    }
    async fn send(&mut self, bytes: &[u8]) -> Result<usize, WiFiInterfaceError<pcap::Error>> {
        self.capture
            .async_io_mut(Interest::WRITABLE, |capture| {
                Ok(capture
                    .sendpacket(bytes)
                    .map(|_| bytes.len())
                    .map_err(WiFiInterfaceError::PlatformSpecificError))
            })
            .await
            .unwrap()
    }
    fn is_5ghz_supported(&self) -> bool {
        true
    }
    fn get_highest_channel_width(&self) -> ChannelWidth {
        ChannelWidth::EightyMHZ
    }
}
