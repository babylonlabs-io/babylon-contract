# testdata

This folder contains test data for testing Babylon smart contract states.

## Testdata for BTC light client

The test data `btclightclient.json` for BTC light client contains a list of BTC headers on Bitcoin mainnet.
The data is obtained from Babylon alpha testnet via the following script:

```bash
curl http://rpc.testnet.babylonchain.io:1317/babylon/btclightclient/v1/mainchain | jq .headers > btclightclient.json
```