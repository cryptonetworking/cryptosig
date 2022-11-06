package ed25519

import (
	"bytes"
	lib "crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/cryptonetworking/cryptosig"
	"math/big"
	"time"
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
	return e.EncodeSig(sig)
}

const Algo = "ed25519"

func (ed25519) Algo() string {
	return Algo
}

func (ed25519) DecodeSK(b []byte) (any, error) {
	if len(b) != lib.PrivateKeySize {
		return nil, errors.New("invalid bytes length")
	}
	return lib.PrivateKey(b), nil
}

func (ed25519) DecodePK(b []byte) (any, error) {
	if len(b) != lib.PublicKeySize {
		return nil, errors.New("invalid bytes length")
	}

	return lib.PublicKey(b), nil
}

func (ed25519) DecodeSig(b []byte) (any, error) {
	if len(b) != lib.SignatureSize {
		return nil, errors.New("invalid bytes length")
	}
	return b, nil
}

func (ed25519) EncodeSK(sk any) []byte {
	return sk.(lib.PrivateKey)
}

func (ed25519) EncodePK(pk any) []byte {
	return pk.(lib.PublicKey)
}

func (ed25519) EncodeSig(sig any) []byte {
	return sig.([]byte)
}

func (ed25519) Sign(sk any, bytes []byte) any {
	return lib.Sign(sk.(lib.PrivateKey), bytes)
}

func (ed25519) Derive(sk any) any {
	return lib.PublicKey(sk.(lib.PrivateKey)[lib.PrivateKeySize-lib.PublicKeySize:])
}

func (ed25519) New() any {
	_, sk, err := lib.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return lib.PrivateKey(sk)
}
func (ed25519) TLS(p any) *tls.Certificate {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certb, err := x509.CreateCertificate(rand.Reader, &template, &template, (p.(lib.PrivateKey)).Public(), p)
	if err != nil {
		panic(err)
	}
	out := bytes.NewBuffer(nil)
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certb})
	if err != nil {
		panic(err)
	}
	pb, err := x509.MarshalPKCS8PrivateKey(p)
	if err != nil {
		panic(err)
	}
	err = pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: pb})
	if err != nil {
		panic(err)
	}
	cert, err := tls.X509KeyPair(out.Bytes(), out.Bytes())
	if err != nil {
		panic(err)
	}
	return &cert
}
func (ed25519) Verify(sig any, pk any, msg []byte) error {
	if lib.Verify(pk.(lib.PublicKey), msg, sig.([]byte)) {
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
