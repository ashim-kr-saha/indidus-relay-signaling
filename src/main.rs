use clap::Parser;
use indidus_relay_signaling::{Config, server};
use std::path::Path;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,

    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level);

    // Load config
    let config = match Config::load(cli.config.as_deref().map(Path::new)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error loading config: {e}");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        "Starting Indidus Relay & Signaling Server v{}",
        env!("CARGO_PKG_VERSION")
    );

    if let Err(e) = server::run(config).await {
        tracing::error!("Server error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn init_logging(level: &str) {
    use tracing_subscriber::{fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().pretty())
        .init();
}
