use std::fmt::Display;

use anyhow::Result;
use bitcoin::{Address, Block, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::{Deserialize, Serialize};
use surrealdb::{
    engine::remote::ws::Ws,
    opt::{auth::Root, Resource},
    sql::{Id, Table, Thing},
    Surreal,
};
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
const ADDRESS_TABLE: &str = "address";
const OUTPUTS_EDGE: &str = "outputs";
const SPENT_BY_EDGE: &str = "spent_by";
const REWARDS_EDGE: &str = "rewards";

#[derive(Debug, Deserialize)]
struct Record {
    #[allow(dead_code)]
    id: Thing,
}

#[tokio::main]
async fn main() {
    run().await.unwrap();
    //surreal_example::run().await.unwrap();
}

async fn run() -> Result<()> {
    let cfg = surrealdb::opt::Config::default();
    // Create database connection
    let db = Surreal::new::<Ws>(("127.0.0.1:8000", cfg)).await?;

    // Signin as a namespace, database, or root user
    db.signin(Root {
        username: "root",
        password: "root",
    })
    .await?;

    // Select a specific namespace / database
    db.use_ns("test").use_db("bitcoin-main").await?;

    // delete all records from blocks
    let mut r = db
        .query(format!(
            "DELETE {};DELETE {};DELETE {};DELETE {};DELETE {};DELETE {};DELETE {};",
            OUTPUTS_EDGE,
            SPENT_BY_EDGE,
            TRANSACTION_TABLE,
            TIP_HIST_TABLE,
            BLOCK_TABLE,
            TXOUT_TABLE,
            ADDRESS_TABLE
        ))
        .await?;
    for e in r.take_errors() {
        Err(e.1)?;
    }
    assert_eq!(r.num_statements(), 7);

    let btc = Client::new(
        "localhost:8332",
        Auth::UserPass(
            "bitcoin-surrealdb".into(),
            "o4ka4wx3i0wxar0bec2w1sm9h".into(),
        ),
    )?;
    let blockchain_info = btc.get_blockchain_info()?;
    println!("blockchain_info:\n{:?}", blockchain_info);
    let tip_hash = btc.get_best_block_hash()?;
    let header = btc.get_block_header_info(&tip_hash)?;
    println!("best block hash:\n{}", tip_hash);
    println!("block info:\n{:?}", header);
    let mut height = 0;
    let mut buf = String::new();
    let network = Network::from_core_arg(blockchain_info.chain.as_str())?;
    while let Ok(block_hash) = btc.get_block_hash(height) {
        println!("block [{}]:{}", height, block_hash);
        //let block = btc.get_block(&block_hash)?;
        // let header = btc.get_block_header(&block_hash)?;
        // let header_info = btc.get_block_header_info(&block_hash)?;
        let block = btc.get_block(&block_hash)?;

        //dbg!(header);
        //dbg!(header_info);
        block_to_surql(&mut buf, height, block, network);
        //dbg!(&buf);
        let mut r = db.query(&buf).await?;
        for e in r.take_errors() {
            dbg!(&e);
            Err(e.1)?;
        }
        //dbg!(r);
        buf.clear();
        //dbg!(created);
        height += 1;
    }
    Ok(())
}

fn block_to_surql(buf: &mut String, height: u64, block: Block, network: Network) {
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
    buf.push_str("} RETURN NONE;\n");

    if let Some(coinbase) = block.txdata.first() {
        buf.push_str("RELATE ");
        buf.push_str(&block_id);
        buf.push_str("->");
        buf.push_str(REWARDS_EDGE);
        buf.push_str("->");
        push_id_str_disp(buf, TRANSACTION_TABLE, coinbase.txid());
        buf.push_str(" RETURN NONE;\n");
    }

    buf.push_str("UPDATE ");
    buf.push_str(&format!("{}:{}", TIP_HIST_TABLE, height));
    buf.push_str(" CONTENT {");
    push_pair_raw(buf, "block_id", &block_id);
    buf.push_str("} RETURN NONE;\n");

    for (idx, transaction) in block.txdata.into_iter().enumerate() {
        let txid_raw_str = transaction.txid().to_string();
        let mut transaction_id = String::new();
        push_id_str(&mut transaction_id, TRANSACTION_TABLE, &txid_raw_str);
        buf.push_str("UPDATE ");
        buf.push_str(&transaction_id);
        buf.push_str(" CONTENT {");
        push_pair_raw(buf, "block_id", &block_id);
        push_pair_raw_disp(buf, "block_tx_index", idx);
        push_pair_raw_disp(buf, "rbf", transaction.is_explicitly_rbf());
        buf.push_str("} RETURN NONE;\n");

        for (output, vout) in transaction.output.into_iter().zip(0_u32..) {
            let txout_id = prepare_txout_id(&txid_raw_str, vout);

            buf.push_str("UPDATE ");
            buf.push_str(&txout_id);
            buf.push_str(" CONTENT {");
            push_pair_raw_disp(buf, "value_sats", output.value);
            let address = Address::from_script(output.script_pubkey.as_script(), network);
            if let Ok(address) = address {
                push_link_str_disp(buf, "address_id", ADDRESS_TABLE, address);
            } else if let Some(pubkey) = output.script_pubkey.p2pk_public_key() {
                push_link_str_disp(buf, "address_id", ADDRESS_TABLE, pubkey);
            } else if output.script_pubkey.is_op_return() {
                push_pair_raw_disp(buf, "op_return", true);
            } else {
                push_link_str(
                    buf,
                    "address_id",
                    ADDRESS_TABLE,
                    format!("raw_{}", output.script_pubkey.script_hash()),
                );
            }
            buf.push_str("} RETURN NONE;\n");

            buf.push_str("RELATE ");
            buf.push_str(&transaction_id);
            buf.push_str("->");
            buf.push_str(OUTPUTS_EDGE);
            buf.push_str("->");
            buf.push_str(&txout_id);
            buf.push_str(" CONTENT {");
            push_pair_raw_disp(buf, "vout", vout);
            buf.push_str("} RETURN NONE;\n");
        }

        for (vin, input) in transaction.input.into_iter().enumerate() {
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
            buf.push_str("} RETURN NONE;\n");
        }
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
