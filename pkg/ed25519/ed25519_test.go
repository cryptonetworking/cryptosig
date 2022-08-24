package ed25519

import (
	"github.com/cryptonetworking/cryptosig"
	"testing"
)

func TestEd25519(t *testing.T) {
	for range make([]struct{}, 10) {
		err := cryptosig.TestAlgo(Interface())
		if err != nil {
			t.Fatal(err)
		}
	}
}
