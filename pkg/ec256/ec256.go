package ec256

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"github.com/cryptonetworking/cryptography"
	"github.com/itsabgr/go-handy"
)
import lib "crypto/ecdsa"

type ec256 struct{}

const Algo = "ec256"

func (ec256) Algo() string {
	return Algo
}

func (ec256) DecodeSK(b []byte) (any, error) {
	return x509.ParseECPrivateKey(b)
}

func (ec256) DecodePK(b []byte) (any, error) {
	pub, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	return pub.(*lib.PublicKey), nil
}

func (ec256) DecodeSig(bytes []byte) (any, error) {
	return bytes, nil
}

func (ec256) EncodeSK(sk any) []byte {
	b, err := x509.MarshalECPrivateKey(sk.(*lib.PrivateKey))
	handy.Throw(err)
	return b
}

func (ec256) EncodePK(pk any) []byte {
	b, err := x509.MarshalPKIXPublicKey(pk)
	handy.Throw(err)
	return b
}

func (ec256) EncodeSig(sig any) []byte {
	return sig.([]byte)
}

func (ec256) Sign(sk any, msg []byte) any {
	sig, err := lib.SignASN1(rand.Reader, sk.(*lib.PrivateKey), msg)
	handy.Throw(err)
	return sig
}

func (ec256) Derive(sk any) any {
	return &sk.(*lib.PrivateKey).PublicKey
}

func (ec256) New() any {
	sk, err := lib.GenerateKey(elliptic.P256(), rand.Reader)
	handy.Throw(err)
	return sk
}

func (ec256) Verify(sig any, pk any, msg []byte) error {
	if lib.VerifyASN1(pk.(*lib.PublicKey), msg, sig.([]byte)) {
		return nil
	}
	return errors.New("invalid signature")
}

func init() {
	cryptography.RegisterSigAlgo(ec256{})
}
