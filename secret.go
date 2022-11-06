package cryptosig

import (
	"crypto/tls"
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
func (sk *SecretKey) TLS() *tls.Certificate {
	algo := sk.algo
	return algo.TLS(sk.sk)
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

func (sk *SecretKey) MarshalText() ([]byte, error) {
	panic(errors.New("marshaling secret-key is not allowed and cause security problems"))
}

func (sk *SecretKey) UnmarshalText(b []byte) error {
	kind, name, bin, err := decode(b)
	if err != nil {
		return err
	}
	if kind != "sec" {
		return errors.New("not SecretKey")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return fmt.Errorf("unsupported algorithm %q", name)
	}
	secKey, err := algo.UnmarshalBinarySecretKey(bin)
	if err != nil {
		return err
	}
	sk.algo = algo
	sk.sk = secKey
	return nil
}
func (sk *SecretKey) UnsafeUnmarshalText() ([]byte, error) {
	algo := sk.algo
	name := algo.Algo()
	b := algo.MarshalBinarySecretKey(sk.sk)
	return encode("sec", name, b), nil
}
