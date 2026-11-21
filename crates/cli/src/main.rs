use std::{error::Error, ffi::OsString};

use rust_mhm_core::{Config, run};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = parse_config_path(std::env::args_os().skip(1))?;
    let config = Config::load_async(&config_path).await?;
    run(config).await?;
    Ok(())
}

fn parse_config_path(mut args: impl Iterator<Item = OsString>) -> Result<OsString, Box<dyn Error>> {
    let Some(first) = args.next() else {
        return Ok(OsString::from("config.yaml"));
    };
    if first == "--help" || first == "-h" {
        println!(
            "Usage: rust-mhm [CONFIG.yaml]\n\nRuns the SOCKS5 proxy with DIRECT, HTTP CONNECT, and SOCKS5 outbounds. An optional loopback control API can inspect and change select-group members."
        );
        std::process::exit(0);
    }
    if args.next().is_some() {
        return Err("expected at most one configuration path".into());
    }
    Ok(first)
}
