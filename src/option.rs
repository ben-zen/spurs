// SPDX-FileCopyrightText: Copyright Ben Lewis, 2026.
// SPDX-License-Identifier: Artistic-2.0

use anyhow::{anyhow, ensure, Result};
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
    NtpServers = 42,
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

// See if this can be replaced with size_of::<IPv4Address>
const IP_ADDR_LEN: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct IPv4Address {
    address: [u8; 4]
}

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
pub struct Routers {
    routers: [IPv4Address],
}

#[derive(Debug, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct DnsServers {
    servers: [IPv4Address]
}

#[derive(Debug, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct NtpServers {
    servers: [IPv4Address]
}

#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct RequestedAddress {
    address: IPv4Address,
}

#[derive(Debug, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct ParameterRequest {
    options: [DhcpOptionNumber],
}

#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct RenewalTime {
    seconds: U32,
}

#[derive(Clone, Copy, Debug, Eq, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct RebindTime {
    seconds: U32,
}

#[derive(Debug, Immutable, IntoBytes, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct IrcServers {
    servers: [IPv4Address]
}

#[derive(Debug)]
pub enum DhcpOption<'message> {
    Pad,
    Subnet(&'message SubnetMask),
    Routers(&'message Routers),
    DnsServers(&'message DnsServers),
    NtpServers(&'message NtpServers),
    RequestedAddress(&'message RequestedAddress),
    Operation(&'message DhcpOperation),
    ParameterRequest(&'message ParameterRequest),
    RenewalTime(&'message RenewalTime),
    RebindTime(&'message RebindTime),
    IrcServers(&'message IrcServers),
    Unknown{ number: u8, data: &'message [u8]},
    End,
}

fn take_dhcp_option<'message>(data: &'message [u8]) -> Result<(DhcpOption<'message>, &'message [u8])> {
    // Short-circuit handling of unknown options. This also sets up our subsequent filter stage.
    let Ok((option_number, suffix)) = DhcpOptionNumber::try_ref_from_prefix(data) else {
        let (option_number, rest) = data.split_first().ok_or(anyhow!("expected at least one byte"))?;
        tracing::info!("unknown option received: {option_number}");
        let (length, rest) = rest.split_first().ok_or(anyhow!("a length is expected for all options"))?;
        ensure!(rest.len() <= (*length).into(), "no option should be longer than the remaining data");
        let (data, suffix) = rest.split_at((*length).into());
        return Ok((DhcpOption::Unknown { number: (*option_number), data }, suffix))
    };

    // Pre-filter for the no-data options, so we're not grabbing the wrong portion of this buffer.
    match option_number {
        DhcpOptionNumber::Pad => return Ok((DhcpOption::Pad, suffix)),
        DhcpOptionNumber::End => return Ok((DhcpOption::End, suffix)),
        _ => {},
    }

    // Now we can actually parse options with data to store.
    let (option_header, suffix) = DhcpOptionHeader::try_ref_from_prefix(data).map_err(|e| anyhow!("couldn't parse the option header: {e:?}"))?;
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
        DhcpOptionNumber::NtpServers => {
            ensure!(((option_header.length % IP_ADDR_LEN) == 0) && option_header.length > 0, "ntp servers should be a multiple of an addr length");
            let (ntp_servers, remainder) = NtpServers::try_ref_from_prefix_with_elems(suffix, usize::from(option_header.length / IP_ADDR_LEN)).map_err(|e| anyhow!("couldn't parse ntp servers: {e:?}"))?;
            (DhcpOption::NtpServers(ntp_servers), remainder)
        }
        DhcpOptionNumber::RequestedAddress => {
            ensure!(option_header.length == IP_ADDR_LEN, "this is a one-address option");
            let (requested_address, remainder) = RequestedAddress::try_ref_from_prefix(suffix).map_err(|e| anyhow!("couldn't parse a requested address: {e:?}"))?;
            (DhcpOption::RequestedAddress(requested_address), remainder)
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
        DhcpOptionNumber::RenewalTime => {
            ensure!(usize::from(option_header.length) >= size_of::<RenewalTime>(), "there should be enough data for the option");
            let (renewal_time, remainder) = RenewalTime::try_ref_from_prefix(suffix).map_err(|e| anyhow!("couldn't parse renewal time: {e:?}"))?;
            (DhcpOption::RenewalTime(renewal_time), remainder)
        },
        DhcpOptionNumber::RebindTime => {
            ensure!(usize::from(option_header.length) >= size_of::<RebindTime>(), "there should be enough data for the rebind option");
            let (rebind_time, remainder) = RebindTime::try_ref_from_prefix(suffix).map_err(|e| anyhow!("couldn't parse rebind time: {e:?}"))?;
            (DhcpOption::RebindTime(rebind_time), remainder)
        },
        DhcpOptionNumber::IrcServers => {
            ensure!((option_header.length % IP_ADDR_LEN) == 0 && option_header.length > 0, "irc servers should be a non-zero multiple of the addr length");
            let (irc_servers, remainder) = IrcServers::try_ref_from_prefix_with_elems(suffix, usize::from(option_header.length / IP_ADDR_LEN)).map_err(|e| anyhow!("couldn't parse irc servers: {e:?}"))?;
            (DhcpOption::IrcServers(irc_servers), remainder)
        }
        _ => unimplemented!(":("),
    };
    Ok((option, remainder))
}

pub fn parse_options<'message>(data: &'message [u8]) -> Result<Vec<DhcpOption<'message>>> {
    let mut options = Vec::new();

    let mut cursor = data;
    while !cursor.is_empty() {
        let (option, suffix) = take_dhcp_option(cursor)?;
        cursor = suffix;
        match option {
            DhcpOption::Pad => continue,
            DhcpOption::End => break,
            _ => options.push(option),
        }
    }

    Ok(options)
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;
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
    fn test_parse_routers() -> Result<()> {
        let too_short_bytes = &[3, 2, 192, 168][..];
        take_dhcp_option(too_short_bytes).expect_err("should be a fault");
        let one_route = &[3, 4, 192, 168, 0, 1][..];
        let (solo_route, _) = take_dhcp_option(one_route).expect("this is well-formed");
        let DhcpOption::Routers(routers) = solo_route else {
            bail!("expected a Routers option instead of {solo_route:?}")
        };

        assert_eq!(routers.routers.len(), 1, "only one route");

        let two_routes = &[3, 8, 192, 168, 0, 1, 192, 168, 0, 254][..];
        let (twin_routes, _) = take_dhcp_option(two_routes).expect("this is well-formed");
        let DhcpOption::Routers(routers) = twin_routes else {
            bail!("expected a Routers option instead of {twin_routes:?}")
        };

        assert_eq!(routers.routers.len(), 2, "two routes");

        Ok(())
    }

    #[test]
    fn dns_servers_parse() -> Result<()> {
        let one_server = &[6, 4, 192, 168, 0, 1][..];
        let (one_server_option, _) = take_dhcp_option(one_server).expect("this is well-formed");
        let DhcpOption::DnsServers(servers) = one_server_option else {
            bail!("expected a DnsServers option instead of {one_server_option:?}")
        };

        assert_eq!(servers.servers.len(), 1, "one dns server");

        let two_servers = &[6, 8, 192, 168, 0, 1, 192, 168, 0, 220][..];
        let (two_servers_option, _) = take_dhcp_option(two_servers).expect("this is well-formed");
        let DhcpOption::DnsServers(servers) = two_servers_option else {
            bail!("expected a DnsServers optino instead of {two_servers_option:?}")
        };

        assert_eq!(servers.servers.len(), 2, "two dns servers");

        Ok(())
    }
    
    #[test]
    fn ensure_ntp_servers_parse() -> Result<()> {
        let one_server = &[42, 4, 192, 168, 0, 12][..];
        let (one_server_option, _) = take_dhcp_option(one_server).expect("it's well-formed");
        let DhcpOption::NtpServers(server) = one_server_option else {
            bail!("expected an NtpServers option instead of {one_server_option:?}")
        };
        
        assert_eq!(server.servers.len(), 1, "one server");
        assert_eq!(server.servers[0].address, [192, 168, 0, 12], "should be .12");
        
        let two_servers = &[42, 8, 192, 168, 0, 12, 192, 168, 0, 24][..];
        let (two_servers_option, _) = take_dhcp_option(two_servers).expect("it's well-formed");
        let DhcpOption::NtpServers(servers) = two_servers_option else {
            bail!("expected an NtpServers option instead of {one_server_option:?}")
        };
        
        assert_eq!(servers.servers.len(), 2, "one server");
        assert_eq!(servers.servers[1].address, [192, 168, 0, 24], "should be .24");
        
        Ok(())
    }

    #[test]
    fn requested_address() -> Result<()> {
        let addr_bytes: [u8; 4]  = [192, 168, 0, 13];
        let last_lease = RequestedAddress{address: IPv4Address{ address: addr_bytes }};

        // I haven't really built the into-bytes side of all this, but I'm figuring it out.


        let req_addr_bytes = &[50, 4, 192, 168, 0, 13][..];
        let (requested_address, _) = take_dhcp_option(req_addr_bytes).expect("this is well-formed");
        let DhcpOption::RequestedAddress(req_addr) = requested_address else {
            bail!("expected a RequestedAddress option instead of {requested_address:?}")
        };
        assert_eq!(req_addr, &last_lease, "should be the exact damn same");
        Ok(())
    }

    #[test]
    fn test_parse_operation() -> Result<()> {
        let option_bytes = &[53, 1, 1][..];
        let (option_body, _) = take_dhcp_option(option_bytes).expect("this is a valid option");
        let DhcpOption::Operation(operation) = option_body else {
            bail!("expected an Operation element instead of {option_body:?}")
        };

        assert_matches!(operation, DhcpOperation::Discover, "1 should parse as Discover");
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
        for (parsed, expected) in params.options.iter().zip(options.iter()) {
            assert_eq!(parsed, expected, "{parsed:?} should be the same as {expected:?}");
        }

        Ok(())
    }

    #[test]
    fn test_parse_renewal_time() -> Result<()> {
        let option_bytes = &[58, 4, 0, 0, 0xe, 0x10 ][..];
        let (option_body, _) = take_dhcp_option(option_bytes).expect("this is well-formed");
        let DhcpOption::RenewalTime(renewal) = option_body else {
            bail!("expected renewal time instead of {option_body:?}")
        };

        assert_eq!(renewal.seconds, U32::from(3600), "one hour renewal");
        Ok(())
    }

    #[test]
    fn test_parse_rebind_time() -> Result<()> {
        let option_bytes = &[59, 4, 0, 0x9, 0x3A, 0x80][..];
        let (option_body, _) = take_dhcp_option(option_bytes).expect("this is well-formed");
        let DhcpOption::RebindTime(rebind) = option_body else {
            bail!("expected rebind time instead of {option_body:?}")
        };

        assert_eq!(rebind.seconds, U32::from(3600 * 24 * 7), "it's been one week");
        Ok(())
    }

    #[test]
    fn parse_irc_servers() -> Result<()> {
        let option_bytes = &[74, 4, 192, 168, 0, 17][..];
        let (option_body, _) = take_dhcp_option(option_bytes).expect("this is well-formed");
        let DhcpOption::IrcServers(servers) = option_body else {
            bail!("expected irc servers instead of {option_body:?}")
        };

        assert_eq!(servers.servers.len(), 1, "parsed one URL");

        Ok(())
    }

    #[test]
    fn unknown_option_handling() -> Result<()> {
        let option_bytes = &[251, 3, 1, 2, 3][..];
        let (option_body, _) = take_dhcp_option(option_bytes).expect("it's well-formed but unknown");
        let DhcpOption::Unknown { number, data } = option_body else {
            bail!("expected an unknown option instead of {option_body:?}")
        };

        assert_eq!(number, 251);
        assert_eq!(data.len(), 3);

        Ok(())
    }
}
