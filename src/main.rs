mod cli;
mod config;
mod encryption;

use tracing::{info, error};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the logger
    let subscriber = FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Rust VPN");
    // Parse command line arguments
    let config = cli::parse_args()?;

    // Run in server or client mode based on configuration
    match config.mode {
        config::Mode::Server => {
            info!("Starting in server mode");
            server::run(config).await?;
        }
        config::Mode::Client => {
            info!("Starting in client mode");
            client::run(config).await?;
        }
    }

    info!("VPN service stopped");
    Ok(())
}
