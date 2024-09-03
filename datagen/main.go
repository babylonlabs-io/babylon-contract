package main

import (
	"github.com/babylonlabs-io/babylon-contract/datagen/utils"
)

const (
	mainHeadersLength   = 100
	initialHeaderHeight = 1
	forkHeaderHeight    = 90
	commitPubRandHeight = 100
	commitPubRandAmount = 10
	pubRandIndex        = 1
	testDataPath        = "./packages/test-utils/testdata/"
)

// generating testdata for testing Go <-> Rust protobuf serialisation
func main() {
	utils.GenRawCheckpoint(testDataPath)
	mainHeaders := utils.GenBTCLightClient(initialHeaderHeight, mainHeadersLength, testDataPath)
	utils.GenBTCLightClientFork(mainHeadersLength, mainHeaders[forkHeaderHeight-initialHeaderHeight], testDataPath)
	utils.GenBTCLightClientForkMessages(mainHeadersLength, mainHeaders[forkHeaderHeight-initialHeaderHeight], testDataPath)
	utils.GenBTCTimestamp(testDataPath)
	utils.GenBTCDelegationsAndParams(testDataPath)
	utils.GenEOTSTestData(testDataPath)
	randListInfo, privKey := utils.GenCommitPubRandListMsg(commitPubRandHeight, commitPubRandAmount, pubRandIndex, testDataPath)
	utils.GenAddFinalitySig(commitPubRandHeight, pubRandIndex, randListInfo, privKey, testDataPath, 1)
	// Conflicting signature / double signing
	utils.GenAddFinalitySig(commitPubRandHeight, pubRandIndex, randListInfo, privKey, testDataPath, 2)
}
