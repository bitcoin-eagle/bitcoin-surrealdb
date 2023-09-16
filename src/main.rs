use anyhow::Result;
use bitcoin::{Address, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
mod surreal_example;

#[tokio::main]
async fn main() {
    //run().unwrap();
    surreal_example::run().await.unwrap();
}

fn run() -> Result<()> {
    let c = Client::new(
        "localhost:8332",
        Auth::UserPass(
            "bitcoin-surrealdb".into(),
            "o4ka4wx3i0wxar0bec2w1sm9h".into(),
        ),
    )?;
    let blockchain_info = c.get_blockchain_info()?;
    println!("blockchain_info:\n{:?}", blockchain_info);
    let hash = c.get_best_block_hash()?;
    let header = c.get_block_header_info(&hash)?;
    println!("best block hash:\n{}", hash);
    println!("block info:\n{:?}", header);
    let mut height = 0;
    while let Ok(block_hash) = c.get_block_hash(height) {
        println!("block [{}]:{}", height, block_hash);
        height += 1;
    }
    // let network = Network::from_core_arg(blockchain_info.chain.as_str())?;
    // let block = c.get_block(&hash)?;
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
