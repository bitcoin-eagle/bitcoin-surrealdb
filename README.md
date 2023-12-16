Import into surreal db using command line

```shell
cargo run -r -- export --btc-rpc-url "127.0.0.1:8332" --btc-rpc-user "bitcoin-surrealdb" --btc-rpc-pass "o4ka4wx3i0wxar0bec2w1sm9h" --no-db-transaction -z | xargs -0 -n1 -P5 sh -c 'for arg do echo "importing " "$arg" " ..." ; surreal import -e "http:/127.0.0.1:8000" -u root -p root --namespace test --database bitcoin-main "$arg" ; echo "removing " "$arg" " ..." ; rm "$arg" ;  done' _
```

# Storage Size

Experiment `--from-height=820000 --block-count=10` -> `170M`.
The current blocks (height 820,000) take ~17 MiB per block. That leads
to total size about ~10 TiB. That's impractical for any personal use which is 
necessary for privacy so I'm abandoning using SurrealDB for my needs.