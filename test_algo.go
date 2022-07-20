package cryptosig

import (
	"errors"
	"github.com/itsabgr/go-handy"
)

func TestAlgo(algo SigningAlgo[any, any, any]) error {
	Algo := algo.Algo()
	RegisterSigAlgo(algo)
	sk := New(Algo)
	if sk.Algo() != Algo {
		return errors.New("non-equal algorithm name")
	}
	msg := handy.Rand(512)
	b, err := sk.Sign(msg).MarshalBinary()
	if err != nil {
		return err
	}
	sig, err := UnmarshalBinarySignature(b)
	if err != nil {
		return err
	}
	if sig.Algo() != Algo {
		return errors.New("non-equal algorithm name")
	}
	b, err = sk.UnsafeMarshalBinary()
	if err != nil {
		return err
	}
	sk, err = UnmarshalBinarySecretKey(b)
	if err != nil {
		return err
	}
	if sk.Algo() != Algo {
		return err
	}
	b, err = sk.PublicKey().MarshalBinary()
	if err != nil {
		return err
	}
	pk, err := UnmarshalBinaryPublicKey(b)
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
	sk2 := New(Algo)
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
