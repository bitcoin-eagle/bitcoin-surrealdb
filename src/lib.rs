use std::{fmt::Display, future, path::Path, time::Duration};

use anyhow::{Context, Result};
use async_stream::try_stream;
use bitcoin::{
    address::{Payload, WitnessVersion},
    Address, Block, Network, Script,
};
use bitcoincore_rpc::{bitcoincore_rpc_json::GetBlockHeaderResult, Auth, Client, RpcApi};
use futures_buffered::{FuturesOrderedBounded, FuturesUnorderedBounded};
use futures_util::{pin_mut, stream::StreamExt, Future, Stream, TryFutureExt};
use serde::Deserialize;
use surrealdb::{engine::remote::ws::Ws, opt::auth::Root, sql::Thing, Surreal};
use tokio::task::JoinHandle;

type Db = Surreal<surrealdb::engine::remote::ws::Client>;

mod surreal_example;

// #[derive(Debug, Serialize, Deserialize)]
// struct Block {
//     id: String,
//     prev_id: Thing,
//     height: u64,
// }

const TIP_HIST_TABLE: &str = "tip_hist";
const BLOCK_TABLE: &str = "block";
const TRANSACTION_TABLE: &str = "transaction";
const TXOUT_TABLE: &str = "tx_out";
const SCRIPT_PUBKEY_TABLE: &str = "script_pubkey";
const ADDRESS_TABLE: &str = "address";
const OUTPUTS_EDGE: &str = "outputs";
const SPENT_BY_EDGE: &str = "spent_by";
const REWARDS_EDGE: &str = "rewards";
const CONFIRMS_EDGE: &str = "confirms";
const LOCKED_BY_EDGE: &str = "locked_by";
const AS_ADDRESS_EDGE: &str = "as_address";

#[cfg(debug_assertions)]
const BITCOIN_RPC_CONCURRENCY: usize = 1;
#[cfg(not(debug_assertions))]
const BITCOIN_RPC_CONCURRENCY: usize = 8;
#[cfg(debug_assertions)]
const RAYON_CONCURRENCY_MULTIPLIER: usize = 1;
#[cfg(not(debug_assertions))]
const RAYON_CONCURRENCY_MULTIPLIER: usize = 1;
#[cfg(debug_assertions)]
const SURREAL_CONCURRENCY: usize = 1;
#[cfg(not(debug_assertions))]
const SURREAL_CONCURRENCY: usize = 8;
#[cfg(debug_assertions)]
const BLOCK_CONCURRENCY_MULTIPLIER: usize = 0;
#[cfg(not(debug_assertions))]
const BLOCK_CONCURRENCY_MULTIPLIER: usize = 1;

#[derive(Debug, Deserialize)]
pub struct BitcoinConf {
    pub url: Option<Box<str>>,
    pub user: Option<Box<str>>,
    pub pass: Option<Box<str>>,
    pub cookie_file: Option<Box<str>>,
}

#[derive(Debug, Deserialize)]
pub struct SurrealConf {
    pub url: Box<str>,
    pub user: Box<str>,
    pub pass: Box<str>,
    pub namespace: Box<str>,
    pub database: Box<str>,
}

#[derive(Debug, Deserialize)]
pub struct RunConf {
    pub dir: Box<Path>,
    pub from_height: Option<u64>,
    pub blocks_per_file: Option<u64>,
}

pub async fn run(
    r: impl Into<RunConf>,
    b: impl Into<BitcoinConf>,
    s: impl Into<SurrealConf>,
) -> Result<()> {
    let cfg = surrealdb::opt::Config::default()
        .query_timeout(Duration::from_secs(86400))
        .transaction_timeout(Duration::from_secs(86400));
    // Create database connection
    let db = Surreal::new::<Ws>(("127.0.0.1:8000", cfg)).await?;

    // Signin as a namespace, database, or root user
    db.signin(Root {
        username: "root",
        password: "root",
    })
    .await?;

    // Select a specific namespace / database
    db.use_ns("test").await?;
    let mut r = db.query("REMOVE DATABASE `bitcoin-main`;").await?;
    for e in r.take_errors() {
        dbg!(&e);
        Err(e.1)?;
    }
    assert_eq!(r.num_statements(), 1);

    db.use_db("bitcoin-main").await?;

    // delete all records from blocks
    // let mut r = db
    //     .query(format!(
    //         "DELETE {};DELETE {};DELETE {};DELETE {};DELETE {};DELETE {};DELETE {}; DELETE {}; DELETE {}; DELETE {}; DELETE {}; DELETE {};",
    //         OUTPUTS_EDGE,
    //         SPENT_BY_EDGE,
    //         CONFIRMS_EDGE,
    //         LOCKED_BY_EDGE,
    //         REWARDS_EDGE,
    //         AS_ADDRESS_EDGE,
    //         TRANSACTION_TABLE,
    //         TIP_HIST_TABLE,
    //         BLOCK_TABLE,
    //         TXOUT_TABLE,
    //         ADDRESS_TABLE,
    //         SCRIPT_PUBKEY_TABLE,
    //     ))
    //     .await?;
    // for e in r.take_errors() {
    //     Err(e.1)?;
    // }
    // assert_eq!(r.num_statements(), 12);

    let btc = Client::new(
        "localhost:8332",
        Auth::UserPass(
            "bitcoin-surrealdb".into(),
            "o4ka4wx3i0wxar0bec2w1sm9h".into(),
        ),
    )?;
    let blockchain_info = btc.get_blockchain_info()?;
    println!("blockchain_info:\n{:?}", blockchain_info);

    let threads = tokio_rayon::rayon::current_num_threads();
    let limit = usize::max(1, threads * BLOCK_CONCURRENCY_MULTIPLIER);
    println!("limit: {limit}");
    let network = Network::from_core_arg(blockchain_info.chain.as_str())?;
    let heights = get_block_heights_stream();
    let blocks = map_stream_with(
        heights,
        spawn_blocking_get_block,
        BITCOIN_RPC_CONCURRENCY,
        || {
            future::ready(
                Client::new(
                    "localhost:8332",
                    Auth::UserPass(
                        "bitcoin-surrealdb".into(),
                        "o4ka4wx3i0wxar0bec2w1sm9h".into(),
                    ),
                )
                .context(""),
            )
        },
    );
    let blocks_surqls = map_stream_with(
        blocks,
        |(height, block), net| {
            tokio_rayon::spawn_fifo(move || {
                let mut buf = String::new();
                block_to_surql(&mut buf, height, &block, net);
                println!("3_SURQL_PREPARED block [{}]{}", height, block.block_hash());
                Ok(((height, block.block_hash(), buf), net))
            })
        },
        threads * RAYON_CONCURRENCY_MULTIPLIER,
        || future::ready(Ok(network)),
    );
    let err = map_stream_with(
        blocks_surqls,
        |(height, block_hash, buf), db: Db| async move {
            //dbg!(&buf);
            let r = db.query(&buf).await;
            println!("4_SURQL_EXECUTED block [{}]{}", height, block_hash);
            if let Err(ref e) = r {
                dbg!(e);
            }
            let mut r = r?;
            for e in r.take_errors() {
                dbg!(&e);
                Err(e.1)?;
            }
            Ok(((), db))
        },
        SURREAL_CONCURRENCY,
        || async {
            Ok({
                db.clone()
                // let cfg = surrealdb::opt::Config::default()
                //     .query_timeout(Duration::from_secs(86400))
                //     .transaction_timeout(Duration::from_secs(86400));
                // // Create database connection
                // let db = Surreal::new::<Ws>(("127.0.0.1:8000", cfg)).await?;

                // // Signin as a namespace, database, or root user
                // db.signin(Root {
                //     username: "root",
                //     password: "root",
                // })
                // .await?;

                // // Select a specific namespace / database
                // db.use_ns("test").use_db("bitcoin-main").await?;

                // db
            })
        },
    )
    .filter_map(|r| future::ready(r.err()));
    pin_mut!(err);
    let mut first = None;
    while let Some(e) = err.next().await {
        dbg!(&e);
        if first.is_none() {
            first = Some(e);
        }
    }
    if let Some(e) = first {
        Err(e)?;
    }
    Ok(())
}

fn map_stream_with<FA, A, I, FR, R>(
    stream: impl Stream<Item = Result<I>>,
    mut f: impl FnMut(I, A) -> FR,
    concurrency: usize,
    mut init: impl FnMut() -> FA,
) -> impl Stream<Item = Result<R>>
where
    FR: Future<Output = Result<(R, A)>>,
    FA: Future<Output = Result<A>>,
{
    try_stream! {
        let mut fut = FuturesUnorderedBounded::<FR>::new(concurrency);
        pin_mut!(stream); // needed for iteration
        while let Some(r) = stream.next().await {
            let item = r?;
            let a = if concurrency <= fut.len(){
                let r = fut.next().await.unwrap()?;
                yield r.0;
                r.1
            }else{
                init().await?
            };
            fut.push(f(item, a));
        }
        while let Some(r) = fut.next().await {
            let r = r?;
            yield r.0;
        }
    }
}

fn get_block_heights_stream() -> impl Stream<Item = Result<u64>> {
    try_stream! {
        let (mut btc, header) = tokio::task::spawn_blocking(|| -> Result<(Client, GetBlockHeaderResult)>{
                let btc = Client::new(
                    "localhost:8332",
                    Auth::UserPass(
                        "bitcoin-surrealdb".into(),
                        "o4ka4wx3i0wxar0bec2w1sm9h".into(),
                    ),
                )?;
                let tip_hash = btc.get_best_block_hash()?;
                let header = btc.get_block_header_info(&tip_hash)?;
                println!("best block hash:\n{}", tip_hash);
                println!("block info:\n{:?}", header);
                Ok((btc, header))
        }).await??;
        let mut begin_height = 0;
        let mut end_height = header.height as u64 + 1;
        while begin_height < end_height {
            for height in begin_height..end_height {
                yield height;
            }
            begin_height = end_height;
            let (btc2, header) = tokio::task::spawn_blocking(move || -> Result<(Client, GetBlockHeaderResult)>{
                let tip_hash = btc.get_best_block_hash()?;
                let header = btc.get_block_header_info(&tip_hash)?;
                Ok((btc, header))
            }).await??;
            btc = btc2;
            end_height = header.height as u64 + 1;
        }
    }
}

fn get_blocks_stream() -> impl Stream<Item = Result<(u64, Block)>> {
    async_stream::try_stream! {
        let (mut btc, header) = tokio::task::spawn_blocking(|| -> Result<(Client, GetBlockHeaderResult)>{
                let btc = Client::new(
                    "localhost:8332",
                    Auth::UserPass(
                        "bitcoin-surrealdb".into(),
                        "o4ka4wx3i0wxar0bec2w1sm9h".into(),
                    ),
                )?;
                let tip_hash = btc.get_best_block_hash()?;
                let header = btc.get_block_header_info(&tip_hash)?;
                println!("best block hash:\n{}", tip_hash);
                println!("block info:\n{:?}", header);
                Ok((btc, header))
        }).await??;
        let mut begin_height = 0;
        let mut end_height = header.height as u64 + 1;
        let mut rpc_fut = FuturesOrderedBounded::<JoinHandle<Result<((u64, Block), Client), anyhow::Error>>>::new(BITCOIN_RPC_CONCURRENCY);
        while begin_height < end_height {
            for height in begin_height..end_height {
                let client = if BITCOIN_RPC_CONCURRENCY <= rpc_fut.len() {
                    let a = rpc_fut.next().await.unwrap()??;
                    yield a.0;
                    a.1
                } else {
                    Client::new(
                        "localhost:8332",
                        Auth::UserPass(
                            "bitcoin-surrealdb".into(),
                            "o4ka4wx3i0wxar0bec2w1sm9h".into(),
                        ),
                    )?
                };
                rpc_fut.push_back(tokio::task::spawn_blocking(move || {
                    get_block(height, client)
                }));
            };
            while let Some(a) = rpc_fut.next().await {
                let tup = a??;
                yield tup.0;
            }
            begin_height = end_height;
            let (btc2, header) = tokio::task::spawn_blocking(move || -> Result<(Client, GetBlockHeaderResult)>{
                let tip_hash = btc.get_best_block_hash()?;
                let header = btc.get_block_header_info(&tip_hash)?;
                Ok((btc, header))
            }).await??;
            btc = btc2;
            end_height = header.height as u64 + 1;
        };
    }
}

fn spawn_blocking_get_block(
    height: u64,
    client: Client,
) -> impl Future<Output = Result<((u64, Block), Client)>> {
    tokio::task::spawn_blocking(move || get_block(height, client))
        .map_ok_or_else(|e| Err(e.into()), |r| r)
}

fn get_block(height: u64, client: Client) -> Result<((u64, Block), Client)> {
    println!("0_STARTED height: {}", height);
    let block_hash = {
        let r = client.get_block_hash(height);
        if let Err(ref e) = r {
            dbg!(e);
        }
        r?
    };
    println!("1_GOT_HASH block [{}]:{}", height, block_hash);
    //let block = btc.get_block(&block_hash)?;
    // let header = btc.get_block_header(&block_hash)?;
    // let header_info = btc.get_block_header_info(&block_hash)?;
    let block = {
        let r = client.get_block(&block_hash);
        if let Err(ref e) = r {
            dbg!(e);
        }
        r?
    };
    println!("2_GOT_BLOCK block [{}]:{}", height, block_hash);
    Ok(((height, block), client))
}

fn block_to_surql(buf: &mut String, height: u64, block: &Block, network: Network) {
    buf.push_str("BEGIN TRANSACTION;\n");

    buf.push_str("UPDATE ");
    let mut block_id = String::new();
    push_id_str_disp(&mut block_id, BLOCK_TABLE, block.block_hash());
    buf.push_str(&block_id);
    buf.push_str(" CONTENT {");
    push_link_str_disp(buf, "prev_id", BLOCK_TABLE, block.header.prev_blockhash);
    push_pair_raw_disp(buf, "height", height);
    push_pair_raw(
        buf,
        "time",
        format!("time::from::unix({})", block.header.time),
    );
    buf.push_str("} RETURN NONE PARALLEL;\n");

    if let Some(coinbase) = block.txdata.first() {
        buf.push_str("RELATE ");
        buf.push_str(&block_id);
        buf.push_str("->");
        buf.push_str(REWARDS_EDGE);
        buf.push_str("->");
        push_id_str_disp(buf, TRANSACTION_TABLE, coinbase.txid());
        buf.push_str(" RETURN NONE PARALLEL;\n");
    }

    buf.push_str("UPDATE ");
    buf.push_str(&format!("{}:{}", TIP_HIST_TABLE, height));
    buf.push_str(" CONTENT {");
    push_pair_raw(buf, "block_id", &block_id);
    buf.push_str("} RETURN NONE PARALLEL;\n");

    for (idx, transaction) in block.txdata.iter().enumerate() {
        let txid_raw_str = transaction.txid().to_string();
        let mut transaction_id = String::new();
        push_id_str(&mut transaction_id, TRANSACTION_TABLE, &txid_raw_str);
        buf.push_str("UPDATE ");
        buf.push_str(&transaction_id);
        buf.push_str(" CONTENT {");
        push_pair_raw_disp(buf, "rbf", transaction.is_explicitly_rbf());
        buf.push_str("} RETURN NONE PARALLEL;\n");

        buf.push_str("RELATE ");
        buf.push_str(&block_id);
        buf.push_str("->");
        buf.push_str(CONFIRMS_EDGE);
        buf.push_str("->");
        buf.push_str(&transaction_id);
        buf.push_str(" CONTENT {");
        push_pair_raw_disp(buf, "index", idx);
        buf.push_str("} RETURN NONE PARALLEL;\n");

        for (output, vout) in transaction.output.iter().zip(0_u32..) {
            let txout_id = prepare_txout_id(&txid_raw_str, vout);

            let script_pubkey_id = {
                let mut script_pubkey_id = String::new();
                push_id_str_disp(
                    &mut script_pubkey_id,
                    SCRIPT_PUBKEY_TABLE,
                    output.script_pubkey.wscript_hash(),
                );
                script_pubkey_id
            };
            buf.push_str("UPDATE ");
            buf.push_str(&txout_id);
            buf.push_str(" CONTENT {");
            push_pair_raw_disp(buf, "value_sats", output.value);
            buf.push_str("} RETURN NONE PARALLEL;\n");

            // TODO: INSERT SCRIPT_PUBKEY
            buf.push_str("UPDATE ");
            buf.push_str(&script_pubkey_id);
            buf.push_str(" CONTENT {");
            push_pair_str_disp(
                buf,
                "script_pubkey_hash",
                output.script_pubkey.script_hash(),
            );
            push_pair_str(
                buf,
                "script_pubkey_hex",
                output.script_pubkey.to_hex_string(),
            );
            push_pair_str(
                buf,
                "script_pubkey_asm",
                &output.script_pubkey.to_asm_string(),
            );
            push_pair_raw_disp(
                buf,
                "provably_unspendable",
                output.script_pubkey.is_provably_unspendable(),
            );
            buf.push_str("} RETURN NONE PARALLEL;\n");

            // TODO: RELATE TX_OUT -> locked_by -> SCRIPT_PUBKEY
            buf.push_str("RELATE ");
            buf.push_str(&txout_id);
            buf.push_str("->");
            buf.push_str(LOCKED_BY_EDGE);
            buf.push_str("->");
            buf.push_str(&script_pubkey_id);
            buf.push_str(" CONTENT {");
            buf.push_str("} RETURN NONE PARALLEL;\n");

            if let Ok(address) = Address::from_script(&output.script_pubkey, network) {
                if let Some(t) = address.address_type() {
                    let address_id = {
                        let mut address_id = String::new();
                        push_id_str_disp(&mut address_id, ADDRESS_TABLE, &address);
                        address_id
                    };
                    buf.push_str("UPDATE ");
                    buf.push_str(&address_id);
                    buf.push_str(" CONTENT {");
                    push_pair_str(buf, "type", t.to_string().to_uppercase());
                    buf.push_str("} RETURN NONE PARALLEL;\n");

                    buf.push_str("RELATE ");
                    buf.push_str(&txout_id);
                    buf.push_str("->");
                    buf.push_str(AS_ADDRESS_EDGE);
                    buf.push_str("->");
                    buf.push_str(&address_id);
                    buf.push_str(" CONTENT {");
                    buf.push_str("} RETURN NONE PARALLEL;\n");
                } else {
                    // INFO: non-standard future segwit version
                }
            }

            // let (out_type, address) = parse_script_pubkey(&output.script_pubkey, network);
            // let address_id = {
            //     let mut address_id = String::new();
            //     push_id_str(&mut address_id, ADDRESS_TABLE, &address);
            //     address_id
            // };

            // buf.push_str("UPDATE ");
            // buf.push_str(&address_id);
            // buf.push_str(" CONTENT {");
            // push_pair_str(
            //     buf,
            //     "type",
            //     match out_type {
            //         TxOutType::Address(ref addr) => addr.to_string(),
            //         _ => Into::<&'static str>::into(&out_type).to_string(),
            //     },
            // );
            // //push_pair_str(buf, "type", format!("{:?}", &out_type));
            // push_pair_str_disp(
            //     buf,
            //     "script_pubkey_hash",
            //     output.script_pubkey.script_hash(),
            // );
            // push_pair_str_disp(
            //     buf,
            //     "script_pubkey_wshash",
            //     output.script_pubkey.wscript_hash(),
            // );
            // push_pair_str(
            //     buf,
            //     "script_pubkey_hex",
            //     output.script_pubkey.to_hex_string(),
            // );
            // push_pair_str_disp(buf, "script_pubkey", output.script_pubkey);
            // buf.push_str("} RETURN NONE PARALLEL;\n");

            buf.push_str("RELATE ");
            buf.push_str(&transaction_id);
            buf.push_str("->");
            buf.push_str(OUTPUTS_EDGE);
            buf.push_str("->");
            buf.push_str(&txout_id);
            buf.push_str(" CONTENT {");
            push_pair_raw_disp(buf, "vout", vout);
            buf.push_str("} RETURN NONE PARALLEL;\n");
        }

        for (vin, input) in transaction.input.iter().enumerate() {
            buf.push_str("RELATE ");
            buf.push_str(&prepare_txout_id(
                &input.previous_output.txid.to_string(),
                input.previous_output.vout,
            ));
            buf.push_str("->");
            buf.push_str(SPENT_BY_EDGE);
            buf.push_str("->");
            buf.push_str(&transaction_id);
            buf.push_str(" CONTENT {");
            push_pair_raw_disp(buf, "vin", vin);
            buf.push_str("} RETURN NONE PARALLEL;\n");
        }
    }
    buf.push_str("COMMIT TRANSACTION;\n");
}

#[derive(Debug, strum::IntoStaticStr)]
enum TxOutType {
    P2pk,
    P2ms,
    OpReturn,
    Address,
    NonStandardWitness(WitnessVersion),
    NonStandard,
}

fn parse_script_pubkey(script_pubkey: &Script, network: Network) -> (TxOutType, String) {
    if let Ok(address) = Address::from_script(script_pubkey, network) {
        let out_type = if let Some(out_type) = address.address_type() {
            TxOutType::Address
        } else if let Payload::WitnessProgram(ref prog) = address.payload {
            TxOutType::NonStandardWitness(prog.version())
        } else {
            TxOutType::NonStandard
        };
        (out_type, address.to_string())
    } else if let Some(pubkey) = script_pubkey.p2pk_public_key() {
        (TxOutType::P2pk, pubkey.to_string())
    } else if script_pubkey.is_op_return() {
        (TxOutType::OpReturn, script_pubkey.script_hash().to_string())
    } else {
        // TODO P2ms https://learnmeabitcoin.com/technical/p2ms
        (
            TxOutType::NonStandard,
            script_pubkey.script_hash().to_string(),
        )
    }
}

fn prepare_txout_id(txid_raw_str: &str, vout: u32) -> String {
    let mut txout_id = String::new();
    push_id_str_disp(
        &mut txout_id,
        TXOUT_TABLE,
        format!("{}:{}", &txid_raw_str, vout),
    );
    txout_id
}

#[inline]
fn push_id_str_disp(buf: &mut String, tbl: &str, id: impl Display) {
    push_id_str(buf, tbl, id.to_string());
}

fn push_id_str(buf: &mut String, tbl: &str, id: impl AsRef<str>) {
    buf.push_str(tbl);
    buf.push_str(":`");
    buf.push_str(id.as_ref());
    buf.push('`');
}

#[inline]
fn push_link_str_disp(buf: &mut String, name: &str, tbl: &str, id: impl Display) {
    push_link_str(buf, name, tbl, id.to_string());
}

fn push_link_str(buf: &mut String, name: &str, tbl: &str, id: impl AsRef<str>) {
    buf.push_str(name);
    buf.push(':');
    push_id_str(buf, tbl, id);
    buf.push(',');
}

#[inline]
fn push_pair_str_disp(buf: &mut String, name: &str, value: impl Display) {
    push_pair_str(buf, name, value.to_string())
}

fn push_pair_str(buf: &mut String, name: &str, value: impl AsRef<str>) {
    buf.push_str(name);
    buf.push(':');
    push_str(buf, value);
    buf.push(',');
}

fn push_str(buf: &mut String, value: impl AsRef<str>) {
    buf.push('\'');
    for c in value.as_ref().chars() {
        match c {
            '\u{0000}'..='\u{001f}' => buf.push_str(format!("\\u{:04x}", c as u8).as_str()),
            '\'' => buf.push_str("\\'"),
            '\\' => buf.push_str("\\\\"),
            _ => buf.push(c),
        }
    }
    buf.push('\'');
}

#[inline]
fn push_pair_raw_disp(buf: &mut String, key: &str, value: impl Display) {
    push_pair_raw(buf, key, value.to_string());
}

fn push_pair_raw(buf: &mut String, key: &str, value: impl AsRef<str>) {
    buf.push_str(key);
    buf.push(':');
    buf.push_str(value.as_ref());
    buf.push(',');
}
