package cryptosig

import (
	"bytes"
	"crypto/tls"
	"errors"
	"github.com/mr-tron/base58"
	"strings"
)

func RegisterSigAlgo(algo SigningAlgo[any, any, any]) {
	regSigAlgo[algo.Algo()] = algo
}
func GetAlgo(name string) SigningAlgo[any, any, any] {
	algo, _ := regSigAlgo[name]
	return algo
}
func ListAlgo() []string {
	algos := make([]string, 0, len(regSigAlgo))
	for name := range regSigAlgo {
		algos = append(algos, name)
	}
	return algos
}

var regSigAlgo = make(map[string]SigningAlgo[any, any, any])

func decode(text []byte) (kind string, algo string, b []byte, err error) {
	parts := bytes.SplitN(text, []byte{':'}, 3)
	if len(parts) != 3 {
		return "", "", nil, errors.New("cryptosig: invalid codec")
	}
	b, err = base58.FastBase58Decoding(string(parts[2]))
	if err != nil {
		return
	}
	return string(parts[0]), string(parts[1]), b, nil
}
func encode(kind, algo string, b []byte) []byte {
	return []byte(strings.Join([]string{kind, algo, base58.FastBase58Encoding(b)}, ":"))
}

type SigningAlgo[S, P, Sig any] interface {
	Algo() string
	UnmarshalBinarySecretKey([]byte) (S, error)
	UnmarshalBinaryPublicKey([]byte) (P, error)
	UnmarshalBinarySignature([]byte) (Sig, error)
	MarshalBinarySecretKey(S) []byte
	MarshalBinaryPublicKey(P) []byte
	MarshalBinarySignature(Sig) []byte
	Sign(S, []byte) Sig
	Derive(S) P
	New() S
	Verify(Sig, P, []byte) error
	TLS(P) *tls.Certificate
}
