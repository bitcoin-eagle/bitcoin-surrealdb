mod btc;
mod cli;
mod surreal;

use clap::Parser;
use cli::*;
use env_logger::Env;
use log::*;

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args.verbose {
        Some(ref v) => env_logger::Builder::new()
            .filter_level(v.log_level_filter())
            .init(),
        None => env_logger::Builder::from_env(
            Env::default().default_filter_or(DEFAULT_LOG_LEVEL.as_str()),
        )
        .init(),
    }
    error!("DUMMY ERROR");
    warn!("DUMMY WARN");
    info!("DUMMY INFO");
    debug!("args: {:?}", args);
    trace!("Started!");
    surreal::run(&args.command).await.unwrap();
    //surreal_example::run().await.unwrap();
}
