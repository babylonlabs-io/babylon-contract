package utils

import (
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/babylonlabs-io/babylon/testutil/datagen"
)

const (
	RAW_CKPT_FILENAME = "raw_ckpt.dat"
)

func GenRawCheckpoint(dir string) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomRawCkpt := datagen.GenRandomRawCheckpoint(r)
	randomRawCkpt.EpochNum = 12345
	randomRawCkptBytes, err := randomRawCkpt.Marshal()
	if err != nil {
		panic(err)
	}
	filePath := filepath.Join(dir, RAW_CKPT_FILENAME)
	if err := os.WriteFile(filePath, randomRawCkptBytes, 0644); err != nil {
		panic(err)
	}
}
