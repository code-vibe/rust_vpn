//! Configuration management for the VPN application
use serde::{Serialize, Deserialize};

/// Operation mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Mode {
    Server,
    Client,
}

/// VPN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Operation mode (server or client)
    pub mode: Mode,

    /// Server address (for client mode)
    pub server_address: Option<String>,

    /// Port to listen on (server) or connect to (client)
    pub port: u16,

    /// Network interface to bind to
    pub interface: String,

    /// VPN subnet (CIDR notation)
    pub subnet: String,

    /// MTU size
    pub mtu: u16,

    /// Enable encryption
    pub encryption_enabled: bool,

    /// Enable AI-based anomaly detection
    pub anomaly_detection_enabled: bool,

    /// Enable AI-based smart routing
    pub smart_routing_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Client,
            server_address: None,
            port: 51820,
            interface: "0.0.0.0".to_string(),
            subnet: "10.0.0.0/24".to_string(),
            mtu: 1420,
            encryption_enabled: true,
            anomaly_detection_enabled: false,
            smart_routing_enabled: false,
        }
    }
}