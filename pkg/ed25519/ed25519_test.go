package ed25519

import (
	"github.com/cryptonetworking/cryptography"
	"github.com/itsabgr/go-handy"
	"testing"
)

func TestEd25519(t *testing.T) {
	for range handy.N(10) {
		sk := cryptography.New(Algo)
		if sk.Algo() != Algo {
			t.FailNow()
		}
		msg := cryptography.Rand(int(cryptography.RandN(0, 512)))
		sig, err := cryptography.DecodeSig(sk.Sign(msg).Encode())
		if err != nil {
			t.Fatal(err)
		}
		if sig.Algo() != Algo {
			t.FailNow()
		}
		sk, err = cryptography.DecodeSK(sk.UnsafeEncode())
		if err != nil {
			t.Fatal(err)
		}
		if sk.Algo() != Algo {
			t.FailNow()
		}
		pk, err := cryptography.DecodePK(sk.PK().Encode())
		if err != nil {
			t.Fatal(err)
		}
		if pk.Algo() != Algo {
			t.FailNow()
		}
		err = sig.Verify(pk, msg)
		if err != nil {
			t.Fatal(err)
		}
		err = pk.Verify(sig, msg)
		if err != nil {
			t.Fatal(err)
		}
	}
}
