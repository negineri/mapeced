mod cli;
mod config;
mod daemon;
mod dhcpv6;
mod error;
mod map;
mod netlink;
mod nftables;

use clap::Parser;
use tracing::error;
use tracing_subscriber::EnvFilter;

use cli::Cli;
use config::load_config;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    init_tracing(&cli.log_level);

    let config = match load_config(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    };

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = daemon::runner::run(config).await {
            error!("{e}");
            std::process::exit(1);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        error!("mapeced only supports Linux");
        std::process::exit(1);
    }
}

fn init_tracing(log_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    #[cfg(target_os = "linux")]
    {
        use std::path::Path;
        if Path::new("/run/systemd/journal/socket").exists() {
            let journald = tracing_journald::layer().expect("failed to connect to journald");
            use tracing_subscriber::prelude::*;
            tracing_subscriber::registry()
                .with(filter)
                .with(journald)
                .init();
            return;
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
