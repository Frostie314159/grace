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

use pcap::{Active, Capture, Device, Direction, Linktype, Packet};
use std::{
    io::{self, ErrorKind},
    task::Poll,
};
use tokio::io::{split, unix::AsyncFd, AsyncRead, AsyncWrite, Interest, ReadHalf, WriteHalf};

use crate::hals::{WiFiInterface, WiFiInterfaceError};

use super::linux::LinuxWiFiControlInterface;

pub struct PcapAsyncWrapper {
    inner: AsyncFd<Capture<Active>>,
}
unsafe impl Sync for PcapAsyncWrapper {}
impl PcapAsyncWrapper {
    pub fn new(capture: Capture<Active>) -> Self {
        Self {
            inner: AsyncFd::with_interest(capture, Interest::READABLE | Interest::WRITABLE)
                .unwrap(),
        }
    }
}
impl AsyncRead for PcapAsyncWrapper {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let self_mut = self.get_mut();

        loop {
            let mut guard = futures::ready!(self_mut.inner.poll_read_ready_mut(cx))?;

            match guard.try_io(|inner| {
                let Packet { data, .. } = inner
                    .get_mut()
                    .next_packet()
                    .map_err(|_| io::Error::new(ErrorKind::UnexpectedEof, "Pcap Error."))?;
                let read = data.len();

                buf.initialize_unfilled()[..read].copy_from_slice(data);
                buf.advance(read);

                Ok(read)
            }) {
                Ok(result) => return Poll::Ready(result.map(|_| ())),
                Err(_would_block) => continue,
            }
        }
    }
}
impl AsyncWrite for PcapAsyncWrapper {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let self_mut = self.get_mut();

        loop {
            let mut guard = futures::ready!(self_mut.inner.poll_write_ready_mut(cx))?;

            match guard.try_io(|inner| Ok(inner.get_mut().sendpacket(buf).unwrap())) {
                Ok(_result) => return Poll::Ready(Ok(buf.len())),
                Err(_would_block) => continue,
            }
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
pub struct PcapWiFiInterface;
impl WiFiInterface<pcap::Error> for PcapWiFiInterface {
    type InternalIO = PcapAsyncWrapper;
    async fn new(
        interface_name: &str,
    ) -> Result<
        (
            LinuxWiFiControlInterface,
            ReadHalf<Self::InternalIO>,
            WriteHalf<Self::InternalIO>,
        ),
        WiFiInterfaceError<pcap::Error>,
    > {
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
        let (read_half, write_half) = split(PcapAsyncWrapper::new(capture));
        Ok((
            LinuxWiFiControlInterface::new(interface_name).await,
            read_half,
            write_half,
        ))
    }
}
