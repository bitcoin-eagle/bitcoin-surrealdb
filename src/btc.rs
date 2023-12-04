use anyhow::Result;
use bitcoincore_rpc::{Auth, Client};
use secrecy::ExposeSecret;

use crate::cli::Btc;

pub fn connect(cfg: &Btc) -> Result<Client> {
    Ok(Client::new(
        &cfg.btc_rpc_url,
        Auth::UserPass(
            cfg.btc_rpc_user.to_string(),
            cfg.btc_rpc_pass.expose_secret().to_string(),
        ),
    )?)
}
