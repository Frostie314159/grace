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

use rcap::{AsyncCapture, RCapError};

use crate::hals::{WiFiInterface, WiFiInterfaceError};

use super::linux::LinuxWiFiControlInterface;

pub struct RCapWiFiInterface;
impl WiFiInterface<RCapError> for RCapWiFiInterface {
    async fn new(
        interface_name: &str,
    ) -> Result<(LinuxWiFiControlInterface, AsyncCapture), WiFiInterfaceError<RCapError>> {
        Ok((
            LinuxWiFiControlInterface::new(interface_name).await,
            AsyncCapture::new(interface_name).unwrap(),
        ))
    }
}
