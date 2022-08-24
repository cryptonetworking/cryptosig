package cryptosig

import (
	"crypto/rand"
	"errors"
	"io"
)

func TestAlgo(algo SigningAlgo[any, any, any]) error {
	Algo := algo.Algo()
	RegisterSigAlgo(algo)
	sk := GenerateSecretKey(Algo)
	if sk.Algo() != Algo {
		return errors.New("non-equal algorithm name")
	}
	msg := make([]byte, 512)
	_, err := io.ReadFull(rand.Reader, msg)
	if err != nil {
		panic(err)
	}
	b, err := sk.Sign(msg).MarshalText()
	if err != nil {
		return err
	}
	sig := new(Signature)
	err = sig.UnmarshalText(b)
	if err != nil {
		return err
	}
	if sig.Algo() != Algo {
		return errors.New("non-equal algorithm name")
	}
	b, err = sk.UnsafeUnmarshalText()
	if err != nil {
		return err
	}
	sk = new(SecretKey)
	err = sk.UnmarshalText(b)
	if err != nil {
		return err
	}
	if sk.Algo() != Algo {
		return err
	}
	b, err = sk.PublicKey().MarshalText()
	if err != nil {
		return err
	}
	pk := new(PublicKey)
	err = pk.UnmarshalText(b)
	if err != nil {
		return err
	}
	if pk.Algo() != Algo {
		return errors.New("non-equal algorithm name")
	}
	err = sig.Verify(pk, msg)
	if err != nil {
		return err
	}
	err = pk.Verify(sig, msg)
	if err != nil {
		return err
	}
	sk2 := GenerateSecretKey(Algo)
	err = sk2.PublicKey().Verify(sig, msg)
	if err == nil {
		return errors.New("algorithm failed")
	}
	sig2 := sk2.Sign(msg)
	err = pk.Verify(sig2, msg)
	if err == nil {
		return errors.New("algorithm failed")
	}
	return nil
}
