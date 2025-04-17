//! Network packet processing
use std::net::{Ipv4Addr, Ipv6Addr};
use std::convert::TryFrom;
use tracing::debug;

/// Protocol numbers
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMP: u8 = 1;

/// IPv4 header structure
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
}

/// Errors related to packet operations
#[derive(Debug)]
pub enum PacketError {
    TooShort,
    InvalidVersion,
    InvalidLength,
    UnsupportedProtocol,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::TooShort => write!(f, "Packet too short"),
            PacketError::InvalidVersion => write!(f, "Invalid IP version"),
            PacketError::InvalidLength => write!(f, "Invalid packet length"),
            PacketError::UnsupportedProtocol => write!(f, "Unsupported protocol"),
        }
    }
}

impl std::error::Error for PacketError {}

/// VPN packet structure
#[derive(Debug, Clone)]
pub struct VpnPacket {
    pub buffer: Vec<u8>,
    pub header: Option<Ipv4Header>,
}

impl VpnPacket {
    /// Create a new empty packet
    pub fn new() -> Self {
        VpnPacket {
            buffer: Vec::with_capacity(2048),
            header: None,
        }
    }

    /// Create a packet from raw data
    pub fn from_bytes(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 20 {
            return Err(PacketError::TooShort);
        }

        // Check IP version (first 4 bits)
        let version = (data[0] >> 4) & 0xF;

        match version {
            4 => {
                let mut packet = VpnPacket {
                    buffer: data.to_vec(),
                    header: None,
                };
                packet.parse_ipv4_header()?;
                Ok(packet)
            },
            6 => {
                // IPv6 support could be added here
                Err(PacketError::UnsupportedProtocol)
            },
            _ => Err(PacketError::InvalidVersion),
        }
    }

    /// Parse IPv4 header from the packet
    fn parse_ipv4_header(&mut self) -> Result<(), PacketError> {
        if self.buffer.len() < 20 {
            return Err(PacketError::TooShort);
        }

        let version = (self.buffer[0] >> 4) & 0xF;
        let ihl = self.buffer[0] & 0xF;
        let dscp = self.buffer[1] >> 2;
        let ecn = self.buffer[1] & 0x3;
        let total_length = u16::from_be_bytes([self.buffer[2], self.buffer[3]]);

        // Ensure the buffer is at least as long as the header claims
        if self.buffer.len() < total_length as usize {
            return Err(PacketError::InvalidLength);
        }

        let identification = u16::from_be_bytes([self.buffer[4], self.buffer[5]]);
        let flags = (self.buffer[6] >> 5) & 0x7;
        let fragment_offset = u16::from_be_bytes([
            self.buffer[6] & 0x1F,
            self.buffer[7],
        ]);
        let ttl = self.buffer[8];
        let protocol = self.buffer[9];
        let header_checksum = u16::from_be_bytes([self.buffer[10], self.buffer[11]]);

        let source_ip = Ipv4Addr::new(
            self.buffer[12],
            self.buffer[13],
            self.buffer[14],
            self.buffer[15],
        );

        let dest_ip = Ipv4Addr::new(
            self.buffer[16],
            self.buffer[17],
            self.buffer[18],
            self.buffer[19],
        );

        self.header = Some(Ipv4Header {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            header_checksum,
            source_ip,
            dest_ip,
        });

        Ok(())
    }

    /// Update the checksum in the IPv4 header
    pub fn update_checksum(&mut self) {
        if let Some(header) = &self.header {
            // Set the checksum field to 0 before calculating
            self.buffer[10] = 0;
            self.buffer[11] = 0;

            // Calculate the header checksum
            let mut sum: u32 = 0;

            // Process header in 16-bit chunks
            for i in (0..header.ihl as usize * 4).step_by(2) {
                if i + 1 < self.buffer.len() {
                    let word = u16::from_be_bytes([self.buffer[i], self.buffer[i + 1]]);
                    sum += word as u32;
                }
            }

            // Add carry
            while sum >> 16 != 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            // One's complement
            let checksum = !(sum as u16);

            // Update the packet
            self.buffer[10] = (checksum >> 8) as u8;
            self.buffer[11] = (checksum & 0xFF) as u8;

            // Update the header
            if let Some(header) = &mut self.header {
                header.header_checksum = checksum;
            }
        }
    }

    /// Get payload part of the packet
    pub fn payload(&self) -> &[u8] {
        if let Some(header) = &self.header {
            let header_size = (header.ihl as usize) * 4;
            &self.buffer[header_size..]
        } else {
            &[]
        }
    }

    /// Get mutable reference to payload part of the packet
    pub fn payload_mut(&mut self) -> &mut [u8] {
        if let Some(header) = &self.header {
            let header_size = (header.ihl as usize) * 4;
            &mut self.buffer[header_size..]
        } else {
            &mut []
        }
    }

    /// Get protocol of the packet
    pub fn protocol(&self) -> Option<u8> {
        self.header.as_ref().map(|h| h.protocol)
    }

    /// Get source IP address
    pub fn source_ip(&self) -> Option<Ipv4Addr> {
        self.header.as_ref().map(|h| h.source_ip)
    }

    /// Get destination IP address
    pub fn dest_ip(&self) -> Option<Ipv4Addr> {
        self.header.as_ref().map(|h| h.dest_ip)
    }

    /// Get packet length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Print packet info for debugging
    pub fn debug_info(&self) -> String {
        if let Some(header) = &self.header {
            let protocol_str = match header.protocol {
                IPPROTO_TCP => "TCP",
                IPPROTO_UDP => "UDP",
                IPPROTO_ICMP => "ICMP",
                p => format!("Unknown({})", p).as_str(),
            };

            format!(
                "IPv4 {} -> {} | Proto: {} | Size: {} bytes",
                header.source_ip,
                header.dest_ip,
                protocol_str,
                header.total_length
            )
        } else {
            format!("Unparsed packet, size: {} bytes", self.buffer.len())
        }
    }
}