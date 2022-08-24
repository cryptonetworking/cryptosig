package cryptosig

import (
	"errors"
	"fmt"
)

type Signature struct {
	algo SigningAlgo[any, any, any]
	sig  any
}

func (sig *Signature) Unwrap() any {
	return sig.sig
}

func (sig *Signature) Verify(pk *PublicKey, msg []byte) error {
	algo := sig.algo
	return algo.Verify(sig.sig, pk.Unwrap(), msg)
}
func (sig *Signature) Algo() string {
	return sig.algo.Algo()
}

func (sig *Signature) MarshalText() ([]byte, error) {
	algo := sig.algo
	name := algo.Algo()
	b := algo.MarshalBinarySignature(sig.sig)
	return encode("sig", name, b), nil
}

func (sig *Signature) UnmarshalText(text []byte) error {
	kind, name, p, err := decode(text)
	if err != nil {
		return err
	}
	if kind != "sig" {
		return errors.New("not Signature")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return fmt.Errorf("unsupported algorithm %q", name)
	}
	signature, err := algo.UnmarshalBinarySignature(p)
	if err != nil {
		return err
	}
	sig.sig = signature
	sig.algo = algo
	return nil
}
