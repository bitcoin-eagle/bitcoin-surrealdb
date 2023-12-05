Import into surreal db using command line

```shell
cargo run -r -- export --btc-rpc-url "127.0.0.1:8332" --btc-rpc-user "bitcoin-surrealdb" --btc-rpc-pass "o4ka4wx3i0wxar0bec2w1sm9h" -z | xargs -0 -n1 -P8 sh -c 'for arg do echo "importing " "$arg" " ..." ; surreal import -e "http:/127.0.0.1:8000" -u root -p root --namespace test --database bitcoin-main "$arg" ; echo "removing " "$arg" " ..." ; rm "$arg" ;  done' _
```