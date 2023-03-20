package main

import (
	"os"

	"github.com/babylonchain/babylon/testutil/datagen"
)

// generating testdata for testing Go <-> Rust protobuf serialisation
func main() {
	randomRawCkpt := datagen.GenRandomRawCheckpoint()
	randomRawCkpt.EpochNum = 12345
	randomRawCkptBytes, err := randomRawCkpt.Marshal()
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("raw_ckpt.dat", randomRawCkptBytes, 0644); err != nil {
		panic(err)
	}
}
