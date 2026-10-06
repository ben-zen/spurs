// SPDX-FileCopyrightText: Copyright Ben Lewis, 2026.
// SPDX-License-Identifier: Artistic-2.0

use zerocopy::{byteorder::network_endian::{U16, U32}, TryFromBytes, Unalign};
use zerocopy_derive::*;


// Failing to decode a message with an unknown HardwareType is unappealing, but...
// ... if you _have_ an unknown HardwareType, maybe you can fill me in.
#[derive(Debug, Eq, Immutable, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(u8)]
pub enum HardwareType {
    Reserved = 0,
    Ethernet10Mb = 1,
    AX25 = 3,
    Ieee802 = 6,
    FrameRelay = 15,
    AsynchronousTransferMode = 16, // and 19, and 21... gotta figure that out.
    FibreChannel = 18,
    Serial = 20,
    MilStd188_220 = 22,
    Ieee1394 = 24,
    IpSec = 31,
    InfiniBand = 32,
    Project25 = 33,
    Wiegand = 34,
}

#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
#[repr(transparent)]
struct HardwareTypeByte(u8);

impl HardwareTypeByte {
    fn eval(self) -> Result<HardwareType, u8> {
        let val = self.0;
        HardwareType::try_read_from_bytes(&self.0.to_ne_bytes()).map_err(|_| val)
    }
}

#[derive(Debug, Eq, Immutable, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(u8)]
pub enum DhcpOperation {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Acknowledge = 5,
    NegativeAcknowledge = 6,
    Release = 7,
    Inform = 8,
}

#[derive(Debug, Eq, Immutable, KnownLayout, PartialEq, TryFromBytes, Unaligned)]
#[repr(u8)]
pub enum BootpOperation {
    BootRequest = 1,
    BootReply = 2
}

#[derive(Debug, KnownLayout, Immutable, TryFromBytes, Unaligned)]
#[repr(C)]
pub struct DhcpOptionHeader {
    option_number: u8,
    option_length: u8,
}

// TODO: fill in types
#[derive(KnownLayout, Immutable, /*SplitAt,*/ TryFromBytes, Unaligned)]
#[repr(C)]
pub struct DhcpHeader {
    operation: BootpOperation,
    hw_type: HardwareTypeByte,
    hw_addr_len: u8,
    hops: u8,
    xid: U32,
    secs: U16,
    flags: U16,
    ciaddr: [u8; 4],
    yiaddr: [u8; 4],
    siaddr: [u8; 4],
    giaddr: [u8; 4],
    hw_addr: [u8; 16], // first `hw_addr_len` bytes
    sname: [u8; 64],
    file: [u8; 128]
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{bail, Error, Result};
    
    #[test]
    fn dhcp_operation_from_byte() -> Result<()> {
        let discover_byte = &[0x01][..];
        assert_eq!(DhcpOperation::try_ref_from_bytes(discover_byte)?, &DhcpOperation::Discover);
        
        Ok(())
    }
    
    #[test]
    fn read_dhcp_discover() -> Result<()> {
        let discover_message_bytes = &[
            0x01,
            0x06,
            0x06, // hw_addr_len
            0x00, // hops
            0xA0, 0xB0, 0xC0, 0xD0, // xid
            0x00, 0x00, // secs
            0x00, 0x00, // flags
            0x00, 0x00, 0x00, 0x00, // ciaddr
            0x00, 0x00, 0x00, 0x00, // yiaddr
            0x00, 0x00, 0x00, 0x00, // siaddr
            0x00, 0x00, 0x00, 0x00, // giaddr
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // chaddr
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sname
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // file
            // header end, options begin
            53, 1, 1, // Discover operation
        ][..];
        
        let (discover_header, _options) = DhcpHeader::try_ref_from_prefix(discover_message_bytes).expect("there's a header there for sure");
        
        assert_eq!(discover_header.operation, BootpOperation::BootRequest);
        assert_eq!(discover_header.hw_type.eval().expect("huh?"), HardwareType::Ieee802);
        assert_eq!(usize::from(discover_header.hw_addr_len), 6);
        
        Ok(())
    }
}