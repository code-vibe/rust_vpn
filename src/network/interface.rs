//! Virtual network interface implementation
use std::io::{self, Read, Write};
use tun_tap::{Iface, Mode};
use std::net::Ipv4Addr;
use std::str::FromStr;
use tracing::{info, error, debug};

/// Errors related to network interface operations
#[derive(Debug)]
pub enum InterfaceError {
    CreationFailed(io::Error),
    ConfigurationFailed(String),
    ReadFailed(io::Error),
    WriteFailed(io::Error),
}

impl std::fmt::Display for InterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceError::CreationFailed(e) => write!(f, "Failed to create interface: {}", e),
            InterfaceError::ConfigurationFailed(s) => write!(f, "Failed to configure interface: {}", s),
            InterfaceError::ReadFailed(e) => write!(f, "Failed to read from interface: {}", e),
            InterfaceError::WriteFailed(e) => write!(f, "Failed to write to interface: {}", e),
        }
    }
}

impl std::error::Error for InterfaceError {}

/// Virtual network interface for the VPN
pub struct VpnInterface {
    iface: Iface,
    name: String,
    mtu: u16,
    ip_address: Ipv4Addr,
    netmask: Ipv4Addr,
}

impl VpnInterface {
    /// Create a new VPN interface
    pub fn new(name_prefix: &str, ip_cidr: &str, mtu: u16) -> Result<Self, InterfaceError> {
        // Create TUN interface
        let iface = Iface::new(name_prefix, Mode::Tun)
            .map_err(InterfaceError::CreationFailed)?;

        let name = iface.name().to_string();
        info!("Created TUN interface: {}", name);

        // Parse IP address and netmask from CIDR
        let (ip_address, netmask) = parse_cidr(ip_cidr)
            .map_err(|e| InterfaceError::ConfigurationFailed(e.to_string()))?;

        // Configure interface (platform-specific)
        configure_interface(&name, &ip_address, &netmask, mtu)
            .map_err(|e| InterfaceError::ConfigurationFailed(e.to_string()))?;

        info!("Configured interface {} with IP {}/{} and MTU {}",
            name, ip_address, netmask, mtu);

        Ok(VpnInterface {
            iface,
            name,
            mtu,
            ip_address,
            netmask,
        })
    }

    /// Read a packet from the interface
    pub fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, InterfaceError> {
        self.iface.recv(buffer)
            .map_err(InterfaceError::ReadFailed)
    }

    /// Write a packet to the interface
    pub fn write_packet(&mut self, buffer: &[u8]) -> Result<usize, InterfaceError> {
        self.iface.send(buffer)
            .map_err(InterfaceError::WriteFailed)
    }

    /// Get the interface name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the interface IP address
    pub fn ip_address(&self) -> &Ipv4Addr {
        &self.ip_address
    }

    /// Get the interface netmask
    pub fn netmask(&self) -> &Ipv4Addr {
        &self.netmask
    }

    /// Get the interface MTU
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

/// Parse a CIDR notation to IP address and netmask
fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, Ipv4Addr), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format".into());
    }

    let ip = Ipv4Addr::from_str(parts[0])?;
    let prefix_len: u8 = parts[1].parse()?;

    if prefix_len > 32 {
        return Err("Invalid prefix length".into());
    }

    // Calculate netmask from prefix length
    let netmask_value = !((1u32 << (32 - prefix_len)) - 1);
    let netmask = Ipv4Addr::from(netmask_value);

    Ok((ip, netmask))
}

/// Configure the network interface (platform-specific)
#[cfg(target_os = "linux")]
fn configure_interface(
    name: &str,
    ip: &Ipv4Addr,
    netmask: &Ipv4Addr,
    mtu: u16
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    // Set IP address and netmask
    let status = Command::new("ip")
        .args(["addr", "add", &format!("{}/{}", ip, netmask_bits(netmask)), "dev", name])
        .status()?;

    if !status.success() {
        return Err("Failed to set IP address".into());
    }

    // Set MTU
    let status = Command::new("ip")
        .args(["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"])
        .status()?;

    if !status.success() {
        return Err("Failed to set MTU".into());
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn configure_interface(
    name: &str,
    ip: &Ipv4Addr,
    netmask: &Ipv4Addr,
    mtu: u16
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    // Set IP address and netmask
    let status = Command::new("ifconfig")
        .args([name, "inet", &ip.to_string(), &netmask.to_string(), "up"])
        .status()?;

    if !status.success() {
        return Err("Failed to set IP address".into());
    }

    // Set MTU
    let status = Command::new("ifconfig")
        .args([name, "mtu", &mtu.to_string()])
        .status()?;

    if !status.success() {
        return Err("Failed to set MTU".into());
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn configure_interface(
    name: &str,
    ip: &Ipv4Addr,
    netmask: &Ipv4Addr,
    mtu: u16
) -> Result<(), Box<dyn std::error::Error>> {
    // Windows implementation would be different and more complex
    // This is a placeholder
    Err("Windows implementation not yet available".into())
}

/// Calculate the number of bits in a netmask
fn netmask_bits(netmask: &Ipv4Addr) -> u8 {
    let mut bits = 0;
    let octets = netmask.octets();

    for octet in octets.iter() {
        bits += octet.count_ones() as u8;
    }

    bits
}