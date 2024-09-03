package utils

import (
	"math/rand"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
)

var (
	net = &chaincfg.RegressionNetParams
	r   = rand.New(rand.NewSource(time.Now().Unix()))
)
