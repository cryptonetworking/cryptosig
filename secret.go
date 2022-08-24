package cryptosig

import (
	"encoding/hex"
	"errors"
	"fmt"
)

type SecretKey struct {
	algo SigningAlgo[any, any, any]
	sk   any
}

func (sk *SecretKey) Algo() string {
	return sk.algo.Algo()
}

func (sk *SecretKey) PublicKey() *PublicKey {
	algo := sk.algo
	return &PublicKey{algo, algo.Derive(sk.sk)}
}

func (sk *SecretKey) Sign(msg []byte) *Signature {
	algo := sk.algo
	signature := algo.Sign(sk.sk, msg)
	return &Signature{algo, signature}
}

func (sk *SecretKey) Unwrap() any {
	return sk.sk
}

func GenerateSecretKey(algo string) *SecretKey {
	algorithm := regSigAlgo[algo]
	secKey := algorithm.New()
	return &SecretKey{algorithm, secKey}
}
func (sk *SecretKey) MarshalJSON() ([]byte, error) {
	panic(errors.New("marshaling secret-key is not allowed and can cause security problems"))
}

func (sk *SecretKey) MarshalBinary() ([]byte, error) {
	panic(errors.New("marshaling secret-key is not allowed and can cause security problems"))
}

func (sk *SecretKey) UnmarshalBinary(b []byte) error {
	name, kind, p, err := decode(b)
	if err != nil {
		return err
	}
	if kind != 1 {
		return errors.New("not SecretKey")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return fmt.Errorf("unsupported algorithm %q", name)
	}
	secKey, err := algo.UnmarshalBinarySecretKey(p)
	if err != nil {
		return err
	}
	sk.algo = algo
	sk.sk = secKey
	return nil
}
func (sk *SecretKey) UnmarshalText(data []byte) error {
	x, err := hex.DecodeString(string(data))
	if err != nil {
		return err
	}
	return sk.UnmarshalBinary(x)
}

func (sk *SecretKey) UnsafeMarshalBinary() ([]byte, error) {
	algo := sk.algo
	name := algo.Algo()
	b := algo.MarshalBinarySecretKey(sk.sk)
	return encode(name, 1, b), nil
}
