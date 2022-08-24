package cryptosig

import (
	"errors"
	"fmt"
)

type PublicKey struct {
	algo SigningAlgo[any, any, any]
	pk   any
}

func (pk *PublicKey) MarshalText() ([]byte, error) {
	algo := pk.algo
	name := algo.Algo()
	b := algo.MarshalBinaryPublicKey(pk.pk)
	return encode("pub", name, b), nil
}

func (pk *PublicKey) UnmarshalText(text []byte) error {
	kind, name, bin, err := decode(text)
	if err != nil {
		return err
	}
	if kind != "pub" {
		return errors.New("not PublicKey")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return fmt.Errorf("unsupported algorithm %q", name)
	}
	pubKey, err := algo.UnmarshalBinaryPublicKey(bin)
	if err != nil {
		return err
	}
	pk.algo = algo
	pk.pk = pubKey
	return nil
}

func (pk *PublicKey) Unwrap() any {
	return pk.pk
}

func (pk *PublicKey) Algo() string {
	return pk.algo.Algo()
}

func (pk *PublicKey) Verify(sig *Signature, msg []byte) error {
	algo := pk.algo
	return algo.Verify(sig.Unwrap(), pk.pk, msg)
}
