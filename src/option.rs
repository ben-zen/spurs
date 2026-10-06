// SPDX-FileCopyrightText: Copyright Ben Lewis, 2026.
// SPDX-License-Identifier: Artistic-2.0

use std::num::NonZeroU8;
use anyhow::{anyhow, ensure, Error, Result};
use zerocopy::{byteorder::network_endian::{U16, U32}, TryFromBytes, Unalign};
use zerocopy_derive::*;

use crate::dhcp::DhcpOperation;

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

#[derive(Debug, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
struct Routers {
    routers: [[u8; 4]],
}

#[derive(Debug, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
struct DnsServers {
    routers: [[u8; 4]],
}


#[derive(Debug, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
struct ParameterRequest {
    options: [DhcpOptionNumber],
}

#[derive(Debug)]
enum DhcpOption<'message> {
    Subnet(&'message SubnetMask),
    Routers(&'message Routers),
    DnsServers(&'message DnsServers),
    Operation(&'message DhcpOperation),
    ParameterRequest(&'message ParameterRequest),
}

// return type should be &[u8] as well
// use this as the parsing function 
fn take_dhcp_option<'message>(data: &'message [u8]) -> Result<(DhcpOption<'message>, &'message [u8])> {
    
    let (option_header, suffix) = DhcpOptionHeader::try_read_from_prefix(data).map_err(|e| anyhow!("couldn't parse the option header: {e:?}"))?;
    ensure!(suffix.len() >= option_header.length.into(), "no option length can exceed remaining data");
    let (option, remainder) = match option_header.option {
        DhcpOptionNumber::Subnet => { 
            ensure!(option_header.length == IP_ADDR_LEN, "subnet mask should be an addr length");
            let (subnet_mask, remainder) = SubnetMask::try_ref_from_prefix(suffix).map_err(|e| anyhow!("couldn't parse subnet mask: {e:?}"))?;
            (DhcpOption::Subnet(subnet_mask), remainder)
        },
        DhcpOptionNumber::Routers => {
            ensure!(((option_header.length % IP_ADDR_LEN) == 0) && option_header.length > 0, "routers should be a multiple of an addr length");
            let (routers, remainder) = Routers::try_ref_from_prefix_with_elems(suffix, usize::from(option_header.length / IP_ADDR_LEN)).map_err(|e| anyhow!("couldn't parse routers: {e:?}"))?;
            (DhcpOption::Routers(routers), remainder)
        },
        DhcpOptionNumber::DnsServers => {
            ensure!(((option_header.length % IP_ADDR_LEN) == 0) && option_header.length > 0, "dns servers should be a multiple of an addr length");
            let (dns_servers, remainder) = DnsServers::try_ref_from_prefix_with_elems(suffix, usize::from(option_header.length / IP_ADDR_LEN)).map_err(|e| anyhow!("couldn't parse dns servers: {e:?}"))?;
            (DhcpOption::DnsServers(dns_servers), remainder)
        },
        DhcpOptionNumber::DhcpMessageType => {
            ensure!(option_header.length == 1, "message type is a 1-byte option");
            let (message_type, remainder) = DhcpOperation::try_ref_from_prefix(suffix).map_err(|e| anyhow!("couldn't parse operation: {e:?}"))?;
            (DhcpOption::Operation(message_type), remainder)
        },
        DhcpOptionNumber::ParameterRequest => {
            ensure!(option_header.length >= 1, "there should be at least one requested option");
            let (parameters, remainder) = ParameterRequest::try_ref_from_prefix_with_elems(suffix, usize::from(option_header.length)).map_err(|e| anyhow!("couldn't parse parameters: {e:?}"))?;
            (DhcpOption::ParameterRequest(parameters), remainder)
        },
        _ => unimplemented!(":("),
    };
    Ok((option, remainder))
}


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{bail, Result};
    use tracing::info;

    #[test]
    fn test_parse_subnet() -> Result<()> {
        let option_bytes = &[1, 4, 255, 255, 255, 0][..];
        let (option_body, _) = take_dhcp_option(option_bytes).expect("this better work");
        info!("parsed option number & length, on validate length & data.");
        let DhcpOption::Subnet(subnet) = option_body else {
            bail!("expected a subnet element")
        };
        assert_eq!(subnet.mask, [255, 255, 255, 0], "expecting a small local network");
        Ok(())
    }

    #[test]
    fn test_parse_operation() -> Result<()> {
        let option_bytes = &[53, 1, 1][..];
        let (option_body, _) = take_dhcp_option(option_bytes).expect("this is a valid option");
        let DhcpOption::Operation(operation) = option_body else {
            bail!("expected an Operation element instead of {option_body:?}")
        };

        assert!(matches!(operation, DhcpOperation::Discover), "1 should parse as Discover");
        Ok(())
    }

    #[test]
    fn test_parse_paramrequest() -> Result<()> {
        let option_bytes = &[55, 5, 3, 6, 15, 60, 74][..];
        let (option_body, _) = take_dhcp_option(option_bytes).expect("this is a valid list of valid options");
        let DhcpOption::ParameterRequest(params) = option_body else {
            bail!("expected a parameter request instead of {option_body:?}")
        };

        assert_eq!(params.options.len(), 5, "five options were requested");
        let options = [DhcpOptionNumber::Routers, DhcpOptionNumber::DnsServers, DhcpOptionNumber::DomainName, DhcpOptionNumber::VendorClass, DhcpOptionNumber::IrcServers];
        for (parsed, expected) in params.options.iter().zip(options) {
            assert!(matches!(parsed, expected), "{parsed:?} should be the same as {expected:?}");
        }

        Ok(())
    }
}