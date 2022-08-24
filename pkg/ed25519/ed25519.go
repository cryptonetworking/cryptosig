package ed25519

import (
	lib "crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/cryptonetworking/cryptosig"
)

type ed25519 struct{}

func (e ed25519) UnmarshalBinarySecretKey(b []byte) (any, error) {
	return e.DecodeSK(b)
}

func (e ed25519) UnmarshalBinaryPublicKey(b []byte) (any, error) {
	return e.DecodePK(b)
}

func (e ed25519) UnmarshalBinarySignature(b []byte) (any, error) {
	return e.DecodeSig(b)
}

func (e ed25519) MarshalBinarySecretKey(s any) []byte {
	return e.EncodeSK(s)
}

func (e ed25519) MarshalBinaryPublicKey(p any) []byte {
	return e.EncodePK(p)
}

func (e ed25519) MarshalBinarySignature(sig any) []byte {
	return e.EncodePK(sig)
}

const Algo = "ed25519"

func (ed25519) Algo() string {
	return Algo
}

func (ed25519) DecodeSK(b []byte) (any, error) {
	if len(b) != lib.PrivateKeySize {
		return nil, errors.New("invalid bytes length")
	}
	return []byte(b), nil
}

func (ed25519) DecodePK(b []byte) (any, error) {
	if len(b) != lib.PublicKeySize {
		return nil, errors.New("invalid bytes length")
	}

	return []byte(b), nil
}

func (ed25519) DecodeSig(b []byte) (any, error) {
	if len(b) != lib.SignatureSize {
		return nil, errors.New("invalid bytes length")
	}
	return b, nil
}

func (ed25519) EncodeSK(sk any) []byte {
	return sk.([]byte)
}

func (ed25519) EncodePK(pk any) []byte {
	return pk.([]byte)
}

func (ed25519) EncodeSig(sig any) []byte {
	return sig.([]byte)
}

func (ed25519) Sign(sk any, bytes []byte) any {
	return []byte(lib.Sign(sk.([]byte), bytes))
}

func (ed25519) Derive(sk any) any {
	return []byte((sk.([]byte)[lib.PrivateKeySize-lib.PublicKeySize:]))
}

func (ed25519) New() any {
	_, sk, err := lib.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return []byte(sk)
}

func (ed25519) Verify(sig any, pk any, msg []byte) error {
	if lib.Verify(pk.([]byte), msg, sig.([]byte)) {
		return nil
	}
	return errors.New("invalid signature")
}
func Interface() cryptosig.SigningAlgo[any, any, any] {
	return ed25519{}
}
func init() {
	cryptosig.RegisterSigAlgo(ed25519{})
}
