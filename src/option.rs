// SPDX-FileCopyrightText: Copyright Ben Lewis, 2026.
// SPDX-License-Identifier: Artistic-2.0

use std::num::NonZeroU8;
use anyhow::{anyhow, ensure, Error, Result};
use zerocopy::{byteorder::network_endian::{U16, U32}, TryFromBytes, Unalign};
use zerocopy_derive::*;

#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(u8)]
pub enum DhcpOptionNumber {
    Pad = 0,
    Subnet = 1,
    Routers = 3,
    DnsServers = 6,
    HostName = 12,
    DomainName = 15,
    RequestedAddress = 50,
    LeaseTime = 51,
    ExtendedOptions = 52, // 
    DhcpMessageType = 53, // DhcpOperation
    ServerIdentifier = 54,
    ParameterRequest = 55,
    Message = 56,
    RenewalTime = 58,
    RebindTime = 59,
    VendorClass = 60,
    ClientIdentifier = 61,
    IrcServers = 74,
    ClasslessRoutes = 121,
    End = 255,
}

#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
struct DhcpOptionHeader {
    option: DhcpOptionNumber,
    length: u8,
}

// enum DhcpOptionPayload {
//     Subnet { mask : [u8; 4]},
//     Routers { ip_addrs: [[u8; 4]]},
//     DnsServers { ip_addrs: [[u8; 4]]},
//     HostName { name: [u8] },
//     DomainName { name: [u8] },
//     RequestedAddress { ip_addr: [u8; 4]},
//     LeaseTime { seconds: U32 },
// }

const IP_ADDR_LEN: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct SubnetMask {
    mask: [u8; 4],
}

impl SubnetMask {
    pub fn new(mask: [u8; 4]) -> Self {
        SubnetMask { mask }
    }
}

// #[derive(Clone, Copy, Debug, Eq, Immutable, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
// #[repr(C)]
// struct Routers {
//     routers: [[u8; 4]],
// }
// 
// struct DnsServers {
//     routers: [[u8; 4]],
// }
// 
// struct DhcpOption {
//     
// }

// use this as the parsing function 
fn take_dhcp_option(data: &[u8]) -> Result<(DhcpOptionHeader, SubnetMask, usize)> {
    
    let (option_header, suffix) = DhcpOptionHeader::try_read_from_prefix(data).map_err(|e| anyhow!("couldn't parse the option header: {e:?}"))?;
    match option_header.option {
        DhcpOptionNumber::Subnet => { 
            ensure!(option_header.length == IP_ADDR_LEN, "subnet mask should be an addr length");
            ensure!(suffix.len() >= option_header.length.into(), "data should be a subnet's length");
            let (subnet_mask, _) = SubnetMask::try_read_from_prefix(suffix).map_err(|e| anyhow!("couldn't parse subnet mask: {e:?}"))?;
            Ok((option_header, subnet_mask, size_of::<DhcpOptionHeader>() + size_of::<SubnetMask>()))
        },
        _ => unimplemented!(":(")
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{bail, Result};
    use tracing::info;
    
    #[test]
    fn test_parse_subnet() -> Result<()> {
        let option_bytes = &[1, 4, 255, 255, 255, 0][..];
        let (option_header, option_body, size) = take_dhcp_option(option_bytes).expect("this better work");
        info!("parsed option number & length, on validate length & data.");
        assert_eq!(size, 6);
        assert_eq!(option_header.option, DhcpOptionNumber::Subnet);
        assert_eq!(option_header.length, IP_ADDR_LEN, "there should be a subnet mask length");
        assert_eq!(option_body.mask, [255, 255, 255, 0], "expecting a small local network");
        Ok(())
    }
}