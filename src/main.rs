use anyhow::Result;
use bitcoin::{Address, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::{Deserialize, Serialize};
use surrealdb::{
    engine::remote::ws::Ws,
    opt::{auth::Root, Resource},
    sql::{Id, Table, Thing},
    Surreal,
};
mod surreal_example;

#[derive(Debug, Serialize, Deserialize)]
struct Block {
    id: String,
    prev_id: Thing,
    height: u64,
}

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
    let blocks_str = "blocks";
    let blocks = Resource::Table(Table::from(blocks_str));

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
    let blocks: Vec<Record> = db.delete(blocks_str).await?;
    println!("deleted {} blocks", blocks.len());

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
    while let Ok(block_hash) = btc.get_block_hash(height) {
        println!("block [{}]:{}", height, block_hash);
        //let block = btc.get_block(&block_hash)?;
        let header = btc.get_block_header(&block_hash)?;
        let header_info = btc.get_block_header_info(&block_hash)?;
        //dbg!(header);
        //dbg!(header_info);
        let created: Vec<Record> = db
            .create(blocks_str)
            .content(Block {
                id: block_hash.to_string(),
                prev_id: Thing::from((blocks_str, Id::from(header.prev_blockhash.to_string()))),
                height,
            })
            .await?;
        //dbg!(created);
        height += 1;
    }
    let network = Network::from_core_arg(blockchain_info.chain.as_str())?;
    let block = btc.get_block(&tip_hash)?;
    dbg!(block.header);
    // for transaction in block.txdata {
    //     transaction.is_explicitly_rbf();
    //     println!("txid: {}", transaction.txid());
    //     for input in transaction.input {
    //         println!("\tprevious output: {}", input.previous_output)
    //     }
    //     for output in transaction.output {
    //         let value = output.value;
    //         println!("\tvalue: {}", value);
    //         if let Ok(address) = Address::from_script(output.script_pubkey.as_script(), network) {
    //             println!("\taddress: {}", address);
    //         } else {
    //             println!("\taddress: {}", "{raw-script}");
    //         }
    //     }
    // }
    Ok(())
}
