package ed25519

import (
	"github.com/cryptonetworking/cryptography"
	"github.com/itsabgr/go-handy"
	"testing"
)

func TestEd25519(t *testing.T) {
	for range handy.N(10) {
		cryptography.TestAlgo(t, ed25519{})
	}
}
