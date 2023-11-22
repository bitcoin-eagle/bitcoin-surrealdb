use anyhow::anyhow;
use clap::Parser;
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::{env, path::Path};

use bitcoin_surrealdb::*;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    dir: Box<Path>,
    #[arg(short, long)]
    from_height: Option<u64>,
    #[arg(short, long)]
    blocks_per_file: Option<u64>,
    #[arg(long)]
    bitcoin_url: Box<str>,
    #[arg(long)]
    bitcoin_user: Box<str>,
    #[arg(long)]
    bitcoin_pass: Box<str>,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub debug: bool,
    pub bitcoin: bitcoin_surrealdb::BitcoinConf,
    pub surrealdb: bitcoin_surrealdb::SurrealConf,
    pub run: bitcoin_surrealdb::RunConf,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        let s = Config::builder()
            // Start off by merging in the "default" configuration file
            .add_source(File::with_name("examples/hierarchical-env/config/default"))
            // Add in the current environment file
            // Default to 'development' env
            // Note that this file is _optional_
            .add_source(
                File::with_name(&format!("examples/hierarchical-env/config/{}", run_mode))
                    .required(false),
            )
            // Add in a local configuration file
            // This file shouldn't be checked in to git
            .add_source(File::with_name("examples/hierarchical-env/config/local").required(false))
            // Add in settings from the environment (with a prefix of APP)
            // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
            .add_source(Environment::with_prefix("app"))
            // You may also programmatically change settings
            .set_override("database.url", "postgres://")?
            .build()?;

        // Now that we're done, let's access our configuration
        println!("debug: {:?}", s.get_bool("debug"));
        println!("database: {:?}", s.get::<String>("database.url"));

        // You can deserialize (and thus freeze) the entire configuration as
        s.try_deserialize()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //let args = Args::parse();
    //dbg!(args);
    //Err(anyhow!("internal error").context("context to error"))?;
    let settings = Settings::new()?;
    dbg!(&settings);
    run(settings.run, settings.bitcoin, settings.surrealdb)
        .await
        .unwrap();
    Ok(())
}
