package main

import (
	"encoding/json"
	"github.com/babylonchain/babylon/types"
	"math/rand"
	"os"
	"testing"
	"time"

	bbnapp "github.com/babylonchain/babylon/app"
	txformat "github.com/babylonchain/babylon/btctxformatter"
	"github.com/babylonchain/babylon/crypto/bls12381"
	"github.com/babylonchain/babylon/testutil/datagen"
	testhelper "github.com/babylonchain/babylon/testutil/helper"
	btcctypes "github.com/babylonchain/babylon/x/btccheckpoint/types"
	btclctypes "github.com/babylonchain/babylon/x/btclightclient/types"
	ckpttypes "github.com/babylonchain/babylon/x/checkpointing/types"
	zctypes "github.com/babylonchain/babylon/x/zoneconcierge/types"
	"github.com/boljen/go-bitmap"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

var (
	cdc = bbnapp.GetEncodingConfig().Codec
)

func GenRawCheckpoint() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomRawCkpt := datagen.GenRandomRawCheckpoint(r)
	randomRawCkpt.EpochNum = 12345
	randomRawCkptBytes, err := randomRawCkpt.Marshal()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("./packages/proto/testdata/raw_ckpt.dat", randomRawCkptBytes, 0644); err != nil {
		panic(err)
	}
}

func signBLSWithBitmap(blsSKs []bls12381.PrivateKey, bm bitmap.Bitmap, msg []byte) (bls12381.Signature, error) {
	sigs := []bls12381.Signature{}
	for i := 0; i < len(blsSKs); i++ {
		if bitmap.Get(bm, i) {
			sig := bls12381.Sign(blsSKs[i], msg)
			sigs = append(sigs, sig)
		}
	}
	return bls12381.AggrSigList(sigs)
}

func GenBTCTimestamp(r *rand.Rand) {
	t := &testing.T{}
	valSet, privSigner, err := datagen.GenesisValidatorSetWithPrivSigner(10)
	if err != nil {
		panic(err)
	}
	h := testhelper.NewHelperWithValSet(t, valSet, privSigner)
	ek := &h.App.EpochingKeeper
	zck := h.App.ZoneConciergeKeeper

	// empty BTC timestamp
	btcTs := &zctypes.BTCTimestamp{}
	btcTs.Proof = &zctypes.ProofFinalizedChainInfo{}

	// chain is at height 1 thus epoch 1

	/*
		generate CZ header and its inclusion proof to an epoch
	*/
	// enter block 11, 1st block of epoch 2
	epochInterval := ek.GetParams(h.Ctx).EpochInterval
	for j := 0; j < int(epochInterval); j++ {
		h.Ctx, err = h.ApplyEmptyBlockWithVoteExtension(r)
		h.NoError(err)
	}

	// handle a random header from a random consumer chain
	chainID := datagen.GenRandomHexStr(r, 10)
	height := datagen.RandomInt(r, 100) + 1
	ibctmHeader := datagen.GenRandomIBCTMHeader(r, chainID, height)
	headerInfo := datagen.HeaderToHeaderInfo(ibctmHeader)
	zck.HandleHeaderWithValidCommit(h.Ctx, datagen.GenRandomByteArray(r, 32), headerInfo, false)

	// ensure the header is successfully inserted
	indexedHeader, err := zck.GetHeader(h.Ctx, chainID, height)
	h.NoError(err)

	// enter block 21, 1st block of epoch 3
	for j := 0; j < int(epochInterval); j++ {
		h.Ctx, err = h.ApplyEmptyBlockWithVoteExtension(r)
		h.NoError(err)
	}
	// seal last epoch
	h.Ctx, err = h.ApplyEmptyBlockWithVoteExtension(r)
	h.NoError(err)

	epochWithHeader, err := ek.GetHistoricalEpoch(h.Ctx, indexedHeader.BabylonEpoch)
	h.NoError(err)

	// generate inclusion proof
	proof, err := zck.ProveCZHeaderInEpoch(h.Ctx, indexedHeader, epochWithHeader)
	h.NoError(err)

	btcTs.EpochInfo = epochWithHeader
	btcTs.Header = indexedHeader
	btcTs.Proof.ProofCzHeaderInEpoch = proof

	/*
		seal the epoch and generate ProofEpochSealed
	*/
	// construct the rawCkpt
	// Note that the BlsMultiSig will be generated and assigned later
	bm := datagen.GenFullBitmap()
	sealerBlockhash := ckpttypes.BlockHash(epochWithHeader.SealerBlockHash)
	rawCkpt := &ckpttypes.RawCheckpoint{
		EpochNum:    epochWithHeader.EpochNumber,
		BlockHash:   &sealerBlockhash,
		Bitmap:      bm,
		BlsMultiSig: nil,
	}
	// let the subset generate a BLS multisig over sealer header's app_hash
	multiSig, err := signBLSWithBitmap(h.GenValidators.GetBLSPrivKeys(), bm, rawCkpt.SignedMsg())
	require.NoError(t, err)
	// assign multiSig to rawCkpt
	rawCkpt.BlsMultiSig = &multiSig

	// prove
	btcTs.Proof.ProofEpochSealed, err = zck.ProveEpochSealed(h.Ctx, epochWithHeader.EpochNumber)
	require.NoError(t, err)

	btcTs.RawCheckpoint = rawCkpt

	/*
		forge two BTC headers including the checkpoint
	*/
	// encode ckpt to BTC txs in BTC blocks
	submitterAddr := datagen.GenRandomByteArray(r, txformat.AddressLength)
	rawBTCCkpt, err := ckpttypes.FromRawCkptToBTCCkpt(rawCkpt, submitterAddr)
	h.NoError(err)
	testRawCkptData := datagen.EncodeRawCkptToTestData(rawBTCCkpt)
	idxs := []uint64{datagen.RandomInt(r, 5) + 1, datagen.RandomInt(r, 5) + 1}
	offsets := []uint64{datagen.RandomInt(r, 5) + 1, datagen.RandomInt(r, 5) + 1}
	btcBlocks := []*datagen.BlockCreationResult{
		datagen.CreateBlock(r, 1, uint32(idxs[0]+offsets[0]), uint32(idxs[0]), testRawCkptData.FirstPart),
		datagen.CreateBlock(r, 2, uint32(idxs[1]+offsets[1]), uint32(idxs[1]), testRawCkptData.SecondPart),
	}
	// create MsgInsertBtcSpvProof for the rawCkpt
	msgInsertBtcSpvProof := datagen.GenerateMessageWithRandomSubmitter([]*datagen.BlockCreationResult{btcBlocks[0], btcBlocks[1]})

	// assign BTC submission key and ProofEpochSubmitted
	btcTs.BtcSubmissionKey = &btcctypes.SubmissionKey{
		Key: []*btcctypes.TransactionKey{
			&btcctypes.TransactionKey{Index: uint32(idxs[0]), Hash: btcBlocks[0].HeaderBytes.Hash()},
			&btcctypes.TransactionKey{Index: uint32(idxs[1]), Hash: btcBlocks[1].HeaderBytes.Hash()},
		},
	}
	btcTs.Proof.ProofEpochSubmitted = []*btcctypes.TransactionInfo{
		{
			Key:         btcTs.BtcSubmissionKey.Key[0],
			Transaction: msgInsertBtcSpvProof.Proofs[0].BtcTransaction,
			Proof:       msgInsertBtcSpvProof.Proofs[0].MerkleNodes,
		},
		{
			Key:         btcTs.BtcSubmissionKey.Key[1],
			Transaction: msgInsertBtcSpvProof.Proofs[1].BtcTransaction,
			Proof:       msgInsertBtcSpvProof.Proofs[1].MerkleNodes,
		},
	}

	// save BTC timestamp as test data
	btcTsBytes := cdc.MustMarshal(btcTs)
	if err := os.WriteFile("./testdata/btc_timestamp.dat", btcTsBytes, 0644); err != nil {
		panic(err)
	}

	// save BTC headers that include the BTC timestamp
	if err := os.WriteFile("./testdata/btc_timestamp_header0.dat", btcBlocks[0].HeaderBytes, 0644); err != nil {
		panic(err)
	}
	if err := os.WriteFile("./testdata/btc_timestamp_header1.dat", btcBlocks[1].HeaderBytes, 0644); err != nil {
		panic(err)
	}
}

const mainHeadersLength = 100
const initialHeaderHeight = 1
const forkHeaderHeight = 90

func GenBTCLightClient(r *rand.Rand) []*btclctypes.BTCHeaderInfoResponse {
	headers := datagen.NewBTCHeaderChainWithLength(
		r,
		initialHeaderHeight,
		chaincfg.RegressionNetParams.PowLimit.Uint64(),
		mainHeadersLength).GetChainInfoResponse()
	resp := &btclctypes.QueryMainChainResponse{Headers: headers}
	respBytes := cdc.MustMarshal(resp)
	if err := os.WriteFile("./testdata/btc_light_client.dat", respBytes, 0644); err != nil {
		panic(err)
	}
	return headers
}

func GenBTCLightClientFork(r *rand.Rand, forkHeader *btclctypes.BTCHeaderInfoResponse) {
	height := forkHeader.Height
	length := mainHeadersLength - height + 1 // For an accepted fork

	headers := datagen.NewBTCHeaderChainFromParentInfoResponse(r, forkHeader, uint32(length)).GetChainInfoResponse()
	resp := &btclctypes.QueryMainChainResponse{Headers: headers}
	respBytes := cdc.MustMarshal(resp)
	if err := os.WriteFile("./testdata/btc_light_client_fork.dat", respBytes, 0644); err != nil {
		panic(err)
	}
}

// BtcHeader is a struct for serialising BTC headers.
// Must match the json definition in the Rust code (`./contract/babylon/src/msg/btc_header.rs`).
type BtcHeader struct {
	// Originally protocol version, but repurposed for soft-fork signaling
	Version int32 `json:"version"`
	// Previous block header hash (hex string)
	PrevBlockHash string `json:"prev_blockhash"`
	// Merkle root hash (hex string)
	MerkleRoot string `json:"merkle_root"`
	// Block timestamp
	Time uint32 `json:"time"`
	// The target value below which the blockhash must lie, encoded as a
	// a float (with well-defined rounding, of course).
	Bits uint32 `json:"bits"`
	// Block nonce
	Nonce uint32 `json:"nonce"`
}

// `BtcHeaders` execute msg in Rust code (`./contract/babylon/src/msg/contract.rs`).
type ExecuteMsg struct {
	BtcHeaders *BtcHeaders `json:"btc_headers,omitempty"`
}

type BtcHeaders struct {
	Headers []*BtcHeader `json:"headers"`
}

func GenBTCLightClientForkMessages(r *rand.Rand, forkHeader *btclctypes.BTCHeaderInfoResponse) {
	height := forkHeader.Height
	length := mainHeadersLength - height + 1 // For an accepted fork

	headers := datagen.NewBTCHeaderChainFromParentInfoResponse(r, forkHeader, uint32(length)).GetChainInfoResponse()
	btc_headers := make([]*BtcHeader, len(headers))
	for i := 0; i < len(headers); i++ {
		// Decode the header's header to a BlockHeader struct
		headerBytes, err := types.NewBTCHeaderBytesFromHex(headers[i].HeaderHex)
		if err != nil {
			panic(err)
		}
		blockHeader := headerBytes.ToBlockHeader()

		btc_headers[i] = &BtcHeader{
			Version:       blockHeader.Version,
			PrevBlockHash: blockHeader.PrevBlock.String(),
			MerkleRoot:    blockHeader.MerkleRoot.String(),
			Time:          uint32(blockHeader.Timestamp.Unix()),
			Bits:          blockHeader.Bits,
			Nonce:         blockHeader.Nonce,
		}
	}
	headerChain := &ExecuteMsg{
		BtcHeaders: &BtcHeaders{
			Headers: btc_headers,
		},
	}

	// Marshall to JSON
	respBytes, err := json.Marshal(headerChain)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("./testdata/btc_light_client_fork_msg.json", respBytes, 0644); err != nil {
		panic(err)
	}
}

// generating testdata for testing Go <-> Rust protobuf serialisation
func main() {
	r := rand.New(rand.NewSource(time.Now().Unix()))
	GenRawCheckpoint()
	mainHeaders := GenBTCLightClient(r)
	GenBTCLightClientFork(r, mainHeaders[forkHeaderHeight-initialHeaderHeight])
	GenBTCLightClientForkMessages(r, mainHeaders[forkHeaderHeight-initialHeaderHeight])
	GenBTCTimestamp(r)
}
