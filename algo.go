package cryptosig

import (
	"bytes"
	"github.com/itsabgr/go-handy"
	"github.com/vmihailenco/msgpack/v5"
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

func decode(p []byte) (algo string, kind int8, b []byte, err error) {
	dec := msgpack.NewDecoder(bytes.NewReader(p))
	algo, err = dec.DecodeString()
	if err != nil {
		return
	}
	kind, err = dec.DecodeInt8()
	if err != nil {
		return
	}
	b, err = dec.DecodeBytes()
	if err != nil {
		return
	}
	return
}
func encode(algo string, kind int8, b []byte) []byte {
	buff := bytes.NewBuffer(nil)
	enc := msgpack.NewEncoder(buff)
	handy.Throw(enc.EncodeString(algo))
	handy.Throw(enc.EncodeInt8(kind))
	handy.Throw(enc.EncodeBytes(b))
	return buff.Bytes()
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
}
