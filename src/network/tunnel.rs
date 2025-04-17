//! VPN tunneling implementation
use crate::crypto::CipherSuite;
use crate::network::packet::{VpnPacket, PacketError};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task;
use tracing::{debug, error, info, warn};

/// Maximum packet size
const MAX_PACKET_SIZE: usize = 2048;

/// Tunnel protocol header size
const TUNNEL_HEADER_SIZE: usize = 16;

/// Tunnel protocol version
const TUNNEL_VERSION: u8 = 1;

/// Tunnel packet types
#[repr(u8)]
pub enum TunnelPacketType {
    Data = 0,
    Handshake = 1,
    Keepalive = 2,
}

/// Errors related to tunnel operations
#[derive(Debug)]
pub enum TunnelError {
    IoError(io::Error),
    EncryptionError(String),
    DecryptionError(String),
    PacketError(PacketError),
    InvalidPacket,
    PeerUnreachable,
    Timeout,
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::IoError(e) => write!(f, "I/O error: {}", e),
            TunnelError::EncryptionError(s) => write!(f, "Encryption error: {}", s),
            TunnelError::DecryptionError(s) => write!(f, "Decryption error: {}", s),
            TunnelError::PacketError(e) => write!(f, "Packet error: {}", e),
            TunnelError::InvalidPacket => write!(f, "Invalid packet"),
            TunnelError::PeerUnreachable => write!(f, "Peer unreachable"),
            TunnelError::Timeout => write!(f, "Timeout"),
        }
    }
}

impl std::error::Error for TunnelError {}

impl From<io::Error> for TunnelError {
    fn from(err: io::Error) -> Self {
        TunnelError::IoError(err)
    }
}

impl From<PacketError> for TunnelError {
    fn from(err: PacketError) -> Self {
        TunnelError::PacketError(err)
    }
}

/// Peer information
#[derive(Debug, Clone)]
pub struct Peer {
    pub id: u32,
    pub addr: SocketAddr,
    pub public_key: [u8; 32],
    pub last_handshake: Option<Instant>,
    pub last_received: Option<Instant>,
}

/// VPN tunnel
pub struct VpnTunnel {
    socket: UdpSocket,
    cipher: Option<CipherSuite>,
    peers: Vec<Peer>,
    our_id: u32,
    handshake_interval: Duration,
    keepalive_interval: Duration,
    timeout: Duration,
}

impl VpnTunnel {
    /// Create a new VPN tunnel
    pub fn new(
        bind_addr: &str,
        our_id: u32,
        cipher: Option<CipherSuite>,
    ) -> Result<Self, TunnelError> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;

        info!("Bound UDP socket to {}", bind_addr);

        Ok(VpnTunnel {
            socket,
            cipher,
            peers: Vec::new(),
            our_id,
            handshake_interval: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(10),
            timeout: Duration::from_secs(120),
        })
    }

    /// Add a peer to the tunnel
    pub fn add_peer(&mut self, id: u32, addr: SocketAddr, public_key: [u8; 32]) {
        let peer = Peer {
            id,
            addr,
            public_key,
            last_handshake: None,
            last_received: None,
        };

        self.peers.push(peer);
        info!("Added peer {} at {}", id, addr);
    }

    /// Get peer by ID
    pub fn get_peer(&self, id: u32) -> Option<&Peer> {
        self.peers.iter().find(|p| p.id == id)
    }

    /// Set cipher suite for encryption/decryption
    pub fn set_cipher(&mut self, cipher: CipherSuite) {
        self.cipher = Some(cipher);
    }

    /// Send a packet to a peer
    pub fn send_to_peer(&self, packet: &VpnPacket, peer_id: u32) -> Result<usize, TunnelError> {
        let peer = self.peers.iter()
            .find(|p| p.id == peer_id)
            .ok_or(TunnelError::PeerUnreachable)?;

        // Create tunnel header
        let mut tunnel_packet = Vec::with_capacity(TUNNEL_HEADER_SIZE + packet.len());

        // Add tunnel header:
        // - Version (1 byte)
        tunnel_packet.push(TUNNEL_VERSION);
        // - Packet type (1 byte)
        tunnel_packet.push(TunnelPacketType::Data as u8);
        // - Source ID (4 bytes)
        tunnel_packet.extend_from_slice(&self.our_id.to_be_bytes());
        // - Destination ID (4 bytes)
        tunnel_packet.extend_from_slice(&peer_id.to_be_bytes());
        // - Reserved (6 bytes)
        tunnel_packet.extend_from_slice(&[0u8; 6]);

        // Add the packet data
        tunnel_packet.extend_from_slice(&packet.buffer);

        // Encrypt if cipher is available
        let final_packet = if let Some(cipher) = &self.cipher {
            // Generate nonce (could be based on sequence number)
            let nonce = [0u8; 12]; // This should be unique for each packet!

            // Encrypt
            let mut encrypted = tunnel_packet.clone();
            cipher.encrypt_in_place(&nonce, &[], &mut encrypted)
                .map_err(|e| TunnelError::EncryptionError(e.to_string()))?;

            // Prepend nonce
            let mut final_packet = Vec::with_capacity(nonce.len() + encrypted.len());
            final_packet.extend_from_slice(&nonce);
            final_packet.extend_from_slice(&encrypted);
            final_packet
        } else {
            tunnel_packet
        };

        // Send the packet
        let sent = self.socket.send_to(&final_packet, peer.addr)?;

        debug!("Sent {} bytes to peer {} at {}", sent, peer_id, peer.addr);

        Ok(sent)
    }

    /// Send a handshake packet to a peer
    pub fn send_handshake(&self, peer_id: u32) -> Result<usize, TunnelError> {
        let peer = self.peers.iter()
            .find(|p| p.id == peer_id)
            .ok_or(TunnelError::PeerUnreachable)?;

        // Create handshake packet
        let mut handshake_packet = Vec::with_capacity(TUNNEL_HEADER_SIZE);

        // Add tunnel header:
        // - Version (1 byte)
        handshake_packet.push(TUNNEL_VERSION);
        // - Packet type (1 byte)
        handshake_packet.push(TunnelPacketType::Handshake as u8);
        // - Source ID (4 bytes)
        handshake_packet.extend_from_slice(&self.our_id.to_be_bytes());
        // - Destination ID (4 bytes)
        handshake_packet.extend_from_slice(&peer_id.to_be_bytes());
        // - Reserved (6 bytes)
        handshake_packet.extend_from_slice(&[0u8; 6]);

        // Encrypt if cipher is available
        let final_packet = if let Some(cipher) = &self.cipher {
            // Generate nonce (could be based on sequence number)
            let nonce = [1u8; 12]; // This should be unique for each packet!

            // Encrypt
            let mut encrypted = handshake_packet.clone();
            cipher.encrypt_in_place(&nonce, &[], &mut encrypted)
                .map_err(|e| TunnelError::EncryptionError(e.to_string()))?;

            // Prepend nonce
            let mut final_packet = Vec::with_capacity(nonce.len() + encrypted.len());
            final_packet.extend_from_slice(&nonce);
            final_packet.extend_from_slice(&encrypted);
            final_packet
        } else {
            handshake_packet
        };

        // Send the packet
        let sent = self.socket.send_to(&final_packet, peer.addr)?;

        debug!("Sent handshake to peer {} at {}", peer_id, peer.addr);

        Ok(sent)
    }

    /// Receive a packet from any peer
    pub fn receive(&self) -> Result<(VpnPacket, u32), TunnelError> {
        let mut buffer = [0u8; MAX_PACKET_SIZE];

        // Receive data from the socket
        let (size, src_addr) = self.socket.recv_from(&mut buffer)?;

        if size < TUNNEL_HEADER_SIZE {
            return Err(TunnelError::InvalidPacket);
        }

        // Check if data is encrypted
        let (tunnel_data, peer_id) = if let Some(cipher) = &self.cipher {
            // Extract nonce (first 12 bytes)
            let nonce = &buffer[0..12];
            let encrypted_data = &buffer[12..size];

            // Decrypt
            let mut decrypted = encrypted_data.to_vec();
            cipher.decrypt_in_place(nonce, &[], &mut decrypted)
                .map_err(|e| TunnelError::DecryptionError(e.to_string()))?;

            // Parse tunnel header
            let version = decrypted[0];
            let packet_type = decrypted[1];
            let source_id = u32::from_be_bytes([
                decrypted[2], decrypted[3], decrypted[4], decrypted[5]
            ]);

            (decrypted, source_id)
        } else {
            // Parse tunnel header directly
            let version = buffer[0];
            let packet_type = buffer[1];
            let source_id = u32::from_be_bytes([
                buffer[2], buffer[3], buffer[4], buffer[5]
            ]);

            (buffer[0..size].to_vec(), source_id)
        };

        // Update peer last_received timestamp
        if let Some(peer) = self.peers.iter()
            .position(|p| p.id == peer_id)
            .map(|i| &self.peers[i]) {

            // Update peer timestamp in the future
        }

        // Handle packet based on type
        match tunnel_data[1] {
            x if x == TunnelPacketType::Data as u8 => {
                // Extract IP packet from tunnel data
                let ip_data = &tunnel_data[TUNNEL_HEADER_SIZE..];
                let vpn_packet = VpnPacket::from_bytes(ip_data)?;

                debug!("Received data packet from peer {}: {}",
                    peer_id, vpn_packet.debug_info());

                Ok((vpn_packet, peer_id))
            },
            x if x == TunnelPacketType::Handshake as u8 => {
                debug!("Received handshake from peer {}", peer_id);

                // In a real implementation, we'd perform handshake logic here
                // and potentially update peer information

                // Return an empty packet for now
                Ok((VpnPacket::new(), peer_id))
            },
            x if x == TunnelPacketType::Keepalive as u8 => {
                debug!("Received keepalive from peer {}", peer_id);

                // Return an empty packet
                Ok((VpnPacket::new(), peer_id))
            },
            _ => Err(TunnelError::InvalidPacket),
        }
    }
}