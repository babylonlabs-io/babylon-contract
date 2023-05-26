package main

import (
	"context"
	"math/rand"
	"os"
	"time"

	bbnparams "github.com/babylonchain/babylon/app/params"
	bbndg "github.com/babylonchain/babylon/testutil/datagen"
	zctypes "github.com/babylonchain/babylon/x/zoneconcierge/types"
	bbncfg "github.com/babylonchain/rpc-client/config"
	bbnquery "github.com/babylonchain/rpc-client/query"
)

var (
	ClientCfg = &bbncfg.BabylonQueryConfig{
		RPCAddr: "https://rpc.devnet.babylonchain.io:443",
		Timeout: time.Second * 10,
	}
	cdc = bbnparams.GetEncodingConfig()
)

func genTestDataForProto() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomRawCkpt := bbndg.GenRandomRawCheckpoint(r)
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

	chainListResp, err := client.ConnectedChainList()
	if err != nil {
		panic(err)
	}
	chainID := chainListResp.ChainIds[0]
	var resp *zctypes.QueryFinalizedChainsInfoResponse
	err = client.QueryZoneConcierge(func(ctx context.Context, queryClient zctypes.QueryClient) error {
		var err error
		req := &zctypes.QueryFinalizedChainsInfoRequest{
			ChainIds: []string{chainID},
			Prove:    true,
		}
		resp, err = queryClient.FinalizedChainsInfo(ctx, req)
		return err
	})
	if err != nil {
		panic(err)
	}

	finalizedChainInfo := resp.FinalizedChainsInfo[0]
	finalizedChainInfoBytes, err := cdc.Marshaler.Marshal(finalizedChainInfo)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("../testdata/finalized_chain_info.dat", finalizedChainInfoBytes, 0644); err != nil {
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
