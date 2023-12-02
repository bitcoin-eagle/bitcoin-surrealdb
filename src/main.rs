mod btc;
mod cli;
mod surreal;

use clap::Parser;
use cli::*;
use log::*;

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args.verbose {
        Some(ref v) => env_logger::Builder::new()
            .filter_level(v.log_level_filter())
            .init(),
        None => env_logger::init(),
    }
    debug!("args: {:?}", args);
    trace!("Started!");
    surreal::run(&args.command).await.unwrap();
    //surreal_example::run().await.unwrap();
}
