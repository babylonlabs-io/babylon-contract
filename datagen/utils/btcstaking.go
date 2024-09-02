package utils

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdkmath "cosmossdk.io/math"
	"github.com/babylonlabs-io/babylon/testutil/datagen"
	bbn "github.com/babylonlabs-io/babylon/types"
	"github.com/babylonlabs-io/babylon/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

const (
	FP_FILENAME                = "finality_provider_%d.dat"
	BTC_DEL_FILENAME           = "btc_delegation.dat"
	BTCSTAKING_PARAMS_FILENAME = "btcstaking_params.dat"
)

var (
	net = &chaincfg.RegressionNetParams
	r   = rand.New(rand.NewSource(time.Now().Unix()))
)

func GenParams(dir string) ([]*btcec.PrivateKey, uint32) {
	t := &testing.T{}

	// (3, 5) covenant committee
	covenantSKs, covenantPKs, err := datagen.GenRandomBTCKeyPairs(r, 5)
	require.NoError(t, err)
	covenantQuorum := uint32(3)

	slashingAddress, err := datagen.GenRandomBTCAddress(r, net)
	require.NoError(t, err)

	bsParams := &types.Params{
		CovenantPks:     bbn.NewBIP340PKsFromBTCPKs(covenantPKs),
		CovenantQuorum:  covenantQuorum,
		SlashingAddress: slashingAddress.EncodeAddress(),
	}

	paramsBytes, err := bsParams.Marshal()
	require.NoError(t, err)
	paramsPath := filepath.Join(dir, BTCSTAKING_PARAMS_FILENAME)
	err = os.WriteFile(paramsPath, paramsBytes, 0644)
	require.NoError(t, err)

	return covenantSKs, covenantQuorum
}

func GenFinalityProviders(dir string, numFPs int) {
	t := &testing.T{}

	for i := 1; i <= numFPs; i++ {
		fp, err := datagen.GenRandomFinalityProvider(r)
		require.NoError(t, err)
		fp.ConsumerId = fmt.Sprintf("consumer-%d", i)
		fpBytes, err := fp.Marshal()
		require.NoError(t, err)

		fileName := fmt.Sprintf(FP_FILENAME, i)
		fpPath := filepath.Join(dir, fileName)
		err = os.WriteFile(fpPath, fpBytes, 0644)
		require.NoError(t, err)
	}
}

func GenBTCDelegations(dir string, covenantSKs []*btcec.PrivateKey, covenantQuorum uint32) {
	t := &testing.T{}

	// read params
	params, err := os.ReadFile(filepath.Join(dir, BTCSTAKING_PARAMS_FILENAME))
	require.NoError(t, err)
	bsParams := types.Params{}
	err = bsParams.Unmarshal(params)
	require.NoError(t, err)

	delSK, _, err := datagen.GenRandomBTCKeyPair(r)
	require.NoError(t, err)

	// restaked to a random number of finality providers
	numRestakedFPs := int(datagen.RandomInt(r, 10) + 1)
	_, fpPKs, err := datagen.GenRandomBTCKeyPairs(r, numRestakedFPs)
	require.NoError(t, err)
	fpBTCPKs := bbn.NewBIP340PKsFromBTCPKs(fpPKs)

	stakingTimeBlocks := uint16(5)
	stakingValue := int64(2 * 10e8)

	slashingRate := sdkmath.LegacyNewDecWithPrec(int64(datagen.RandomInt(r, 41)+10), 2)
	unbondingTime := uint16(100) + 1
	slashingChangeLockTime := unbondingTime

	// only the quorum of signers provided the signatures
	covenantSigners := covenantSKs[:covenantQuorum]

	covPKs, err := bbn.NewBTCPKsFromBIP340PKs(bsParams.CovenantPks)
	require.NoError(t, err)

	// construct the BTC delegation with everything
	btcDel, err := datagen.GenRandomBTCDelegation(
		r,
		t,
		net,
		fpBTCPKs,
		delSK,
		covenantSigners,
		covPKs,
		covenantQuorum,
		bsParams.SlashingAddress,
		1000,
		uint64(1000+stakingTimeBlocks),
		uint64(stakingValue),
		slashingRate,
		slashingChangeLockTime,
	)
	require.NoError(t, err)

	btcDelBytes, err := btcDel.Marshal()
	require.NoError(t, err)
	btcDelPath := filepath.Join(dir, BTC_DEL_FILENAME)
	err = os.WriteFile(btcDelPath, btcDelBytes, 0644)
	require.NoError(t, err)
}

func GenBTCDelegationsAndParams(dir string) {
	covenantSKs, covenantQuorum := GenParams(dir)
	GenFinalityProviders(dir, 3)
	GenBTCDelegations(dir, covenantSKs, covenantQuorum)
}
