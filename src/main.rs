use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(name = "mapeced")]
#[command(about = "A CLI application", long_about = None)]
#[command(version)]
struct Cli {
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the main task
    Run {
        /// Target to process
        #[arg(short, long)]
        target: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();

    match cli.command {
        Commands::Run { target } => {
            let target = target.unwrap_or_else(|| "world".to_string());
            run(&target).await?;
        }
    }

    Ok(())
}

async fn run(target: &str) -> Result<()> {
    info!("Running with target: {target}");
    println!("Hello, {target}!");
    Ok(())
}
