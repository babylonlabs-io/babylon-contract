package main

import (
	"context"
	"os"
	"time"

	bbndg "github.com/babylonchain/babylon/testutil/datagen"
	zctypes "github.com/babylonchain/babylon/x/zoneconcierge/types"
	bbncfg "github.com/babylonchain/rpc-client/config"
	bbnquery "github.com/babylonchain/rpc-client/query"
)

var (
	ClientCfg = &bbncfg.BabylonQueryConfig{
		RPCAddr: "http://rpc.devnet.babylonchain.io:26657",
		Timeout: time.Second * 10,
	}
	cdc = bbncfg.GetEncodingConfig()
)

func genTestDataForProto() {
	randomRawCkpt := bbndg.GenRandomRawCheckpoint()
	randomRawCkpt.EpochNum = 12345
	randomRawCkptBytes, err := randomRawCkpt.Marshal()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("../proto/testdata/raw_ckpt.dat", randomRawCkptBytes, 0644); err != nil {
		panic(err)
	}
}

func genTestDataForBabylonEpochChain() {
	client, err := bbnquery.New(ClientCfg)
	if err != nil {
		panic(err)
	}

	var resp *zctypes.QueryFinalizedChainInfoResponse
	err = client.QueryZoneConcierge(func(ctx context.Context, queryClient zctypes.QueryClient) error {
		var err error
		req := &zctypes.QueryFinalizedChainInfoRequest{
			ChainId: "nibiru-itn-1",
			Prove:   true,
		}
		resp, err = queryClient.FinalizedChainInfo(ctx, req)
		return err
	})
	if err != nil {
		panic(err)
	}
	respBytes, err := cdc.Marshaler.Marshal(resp)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("../testdata/finalized_chain_info.dat", respBytes, 0644); err != nil {
		panic(err)
	}
}

func genTestDataForBTCLightclient() {
	client, err := bbnquery.New(ClientCfg)
	if err != nil {
		panic(err)
	}

	resp, err := client.BTCMainChain(nil)
	if err != nil {
		panic(err)
	}
	respBytes, err := cdc.Marshaler.Marshal(resp)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("../testdata/btc_light_client.dat", respBytes, 0644); err != nil {
		panic(err)
	}
}

// generating testdata for testing Go <-> Rust protobuf serialisation
func main() {
	genTestDataForProto()
	genTestDataForBTCLightclient()
	genTestDataForBabylonEpochChain()
}
