package ec256

import (
	"github.com/cryptonetworking/cryptography"
	"github.com/itsabgr/go-handy"
	"testing"
)

func TestEcdsa(t *testing.T) {
	for range handy.N(10) {
		cryptography.TestAlgo(t, ec256{})
	}
}
