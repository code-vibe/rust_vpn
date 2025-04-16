//! This COde contains Command-line interface for the VPN application

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use crate::config::{Config, Mode};
use std::fs;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in server mode
    Server {
        /// Port to listen on
        #[arg(short, long, default_value_t = 51820)]
        port: u16,

        /// Interface to bind to
        #[arg(short, long, default_value = "0.0.0.0")]
        interface: String,
    },
    /// Run in client mode
    Client {
        /// Server address to connect to
        #[arg(short, long)]
        server: String,

        /// Server port to connect to
        #[arg(short, long, default_value_t = 51820)]
        port: u16,
    },
}

/// Parse command line arguments and return a Config
pub fn parse_args() -> Result<Config, Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // If config file is provided, read it
    let mut config = if let Some(config_path) = cli.config {
        let config_content = fs::read_to_string(config_path)?;
        serde_json::from_str(&config_content)?
    } else {
        Config::default()
    };

    // Override config with command line arguments
    match cli.command {
        Commands::Server { port, interface } => {
            config.mode = Mode::Server;
            config.port = port;
            config.interface = interface;
        }
        Commands::Client { server, port } => {
            config.mode = Mode::Client;
            config.server_address = Some(server);
            config.port = port;
        }
    }

    Ok(config)
}