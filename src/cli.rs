use std::path::Path;

use clap::{Args, Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, LogLevel, Verbosity};
use log::*;
use secrecy::Secret;

#[cfg(debug_assertions)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DebugLevel;

#[cfg(debug_assertions)]
impl LogLevel for DebugLevel {
    fn default() -> Option<log::Level> {
        Some(log::Level::Debug)
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[command(flatten)]
    // #[cfg(debug_assertions)]
    // pub verbose: Option<Verbosity<DebugLevel>>,
    // #[cfg(not(debug_assertions))]
    pub verbose: Option<Verbosity<InfoLevel>>,
}

/// Doc comment
#[derive(Subcommand, Debug)]
#[command()]
pub enum Command {
    Export(Export),
    // #[command(name = "remove-database", about = "Removes the database")]
    // RemoveDatabase(SurrealDB),
    Ingest(Ingest),
}

/// Export bitcoin blocks as SurrealQL
///
/// By default, the blocks are exported to the current directory.
/// One block is exported per file. File names are printed to stdout separated
/// by newline.
#[derive(Args, Debug)]
#[command()]
pub struct Export {
    #[command(flatten)]
    btc: Btc,
    /// Export this many blocks per *.surql file.
    #[arg(short = 'b', long, default_value = "1")]
    blocks_per_file: usize,
    /// Export Surreal QL (*.surql) files to this directory.
    #[arg(short = 'o', long, default_value = ".")]
    output_dir: Box<Path>,
    /// Export blocks starting from this height.
    #[arg(short = 'f', long, default_value = "0")]
    from_height: usize,
    /// Stop after exporting this many blocks.
    #[arg(short = 'c', long)]
    block_count: Option<usize>,
    /// Do not envelop the SurrealQL output in a database transaction.
    #[arg(short = 'n', long)]
    no_db_transaction: bool,
    /// file name delimiter is NUL, not newline
    #[arg(short = 'z', long)]
    zero_terminated: bool,
}

#[derive(Args, Debug)]
#[command()]
pub struct Ingest {
    #[command(flatten)]
    sdb: SurrealDB,
    #[command(flatten)]
    btc: Btc,
}

#[derive(Args, Debug)]
pub struct SurrealDB {
    /// SurrealDB URL
    #[arg(short = 'l', long)]
    sdb_url: Box<str>,
    /// SurrealDB username
    #[arg(short = 'u', long)]
    sdb_user: Box<str>,
    /// SurrealDB password
    #[arg(short = 'p', long)]
    sdb_pass: Secret<String>,
    /// SurrealDB namespace
    #[arg(short = 'n', long)]
    sdb_ns: Box<str>,
    /// SurrealDB database name
    #[arg(short = 'd', long)]
    sdb_db: Box<str>,
}

#[derive(Args, Debug)]
pub struct Btc {
    /// Bitcoin Core RPC URL
    #[arg(short = 'L', long)]
    btc_rpc_url: Box<str>,
    /// Bitcoin Core RPC username
    #[arg(short = 'U', long)]
    btc_rpc_user: Box<str>,
    /// Bitcoin Core RPC password
    #[arg(short = 'P', long)]
    btc_rpc_pass: Secret<String>,
}
