package ed25519

import (
	"github.com/cryptonetworking/cryptography"
	"github.com/itsabgr/go-handy"
	"testing"
)

func TestEd25519(t *testing.T) {
	for range handy.N(10) {
		err := cryptography.TestAlgo(ed25519{})
		if err != nil {
			t.Fatal(err)
		}
	}
}
