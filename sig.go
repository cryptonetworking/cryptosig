package cryptography

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/itsabgr/go-handy"
	"github.com/vmihailenco/msgpack/v5"
)

type SigningAlgo[SK, PK, Sig any] interface {
	Algo() string
	DecodeSK([]byte) (SK, error)
	DecodePK([]byte) (PK, error)
	DecodeSig([]byte) (Sig, error)
	EncodeSK(SK) []byte
	EncodePK(PK) []byte
	EncodeSig(Sig) []byte
	Sign(SK, []byte) Sig
	Derive(sk SK) PK
	New() SK
	Verify(sig Sig, pk PK, msg []byte) error
}

var regSigAlgo = make(map[string]SigningAlgo[any, any, any])

type SK struct {
	algo SigningAlgo[any, any, any]
	sk   any
}

type PK struct {
	algo SigningAlgo[any, any, any]
	pk   any
}
type Sig struct {
	algo SigningAlgo[any, any, any]
	sig  any
}

func (sig *Sig) Unwrap() any {
	return sig.sig
}
func (pk *PK) Unwrap() any {
	return pk.pk
}
func (sk *SK) Unwrap() any {
	return sk.sk
}
func RegisterSigAlgo(algo SigningAlgo[any, any, any]) {
	regSigAlgo[algo.Algo()] = algo
}
func Gen(name string) *SK {
	algo := regSigAlgo[name]
	sk := algo.New()
	return &SK{algo, sk}
}
func (sk *SK) Sign(msg []byte) *Sig {
	algo := sk.algo
	sig := algo.Sign(sk.sk, msg)
	return &Sig{algo, sig}
}

func New(algo string) *SK {
	algorithm := regSigAlgo[algo]
	sk := algorithm.New()
	return &SK{algorithm, sk}
}

func encode(algo string, kind int8, b []byte) []byte {
	buff := bytes.NewBuffer(nil)
	enc := msgpack.NewEncoder(buff)
	handy.Throw(enc.EncodeString(algo))
	handy.Throw(enc.EncodeInt8(kind))
	handy.Throw(enc.EncodeBytes(b))
	return buff.Bytes()
}
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

func (sk *SK) UnsafeEncode() []byte {
	algo := sk.algo
	name := algo.Algo()
	b := algo.EncodeSK(sk.sk)
	return encode(name, 1, b)
}
func (sig *Sig) Encode() []byte {
	algo := sig.algo
	name := algo.Algo()
	b := algo.EncodeSig(sig.sig)
	return encode(name, 3, b)
}
func (pk *PK) Encode() []byte {
	algo := pk.algo
	name := algo.Algo()
	b := algo.EncodePK(pk.pk)
	return encode(name, 2, b)
}

func DecodeSK(b []byte) (*SK, error) {
	name, kind, p, err := decode(b)
	if err != nil {
		return nil, err
	}
	if kind != 1 {
		return nil, errors.New("not sk")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return nil, fmt.Errorf("unsupported algorithm %q", name)
	}
	sk, err := algo.DecodeSK(p)
	if err != nil {
		return nil, err
	}
	return &SK{algo, sk}, nil
}
func DecodePK(b []byte) (*PK, error) {
	name, kind, p, err := decode(b)
	if err != nil {
		return nil, err
	}
	if kind != 2 {
		return nil, errors.New("not pk")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return nil, fmt.Errorf("unsupported algorithm %q", name)
	}
	pk, err := algo.DecodePK(p)
	if err != nil {
		return nil, err
	}
	return &PK{algo, pk}, nil
}
func DecodeSig(b []byte) (*Sig, error) {
	name, kind, p, err := decode(b)
	if err != nil {
		return nil, err
	}
	if kind != 3 {
		return nil, errors.New("not sig")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return nil, fmt.Errorf("unsupported algorithm %q", name)
	}
	sig, err := algo.DecodeSig(p)
	if err != nil {
		return nil, err
	}
	return &Sig{algo, sig}, nil
}
func (sk *SK) PK() *PK {
	algo := sk.algo
	pk := algo.Derive(sk.sk)
	return &PK{algo, pk}
}
func (pk *PK) Verify(sig *Sig, msg []byte) error {
	algo := pk.algo
	return algo.Verify(sig.sig, pk.pk, msg)
}
func (sig *Sig) Verify(pk *PK, msg []byte) error {
	algo := sig.algo
	return algo.Verify(sig.sig, pk.pk, msg)
}

func (sig *Sig) Algo() string {
	return sig.algo.Algo()
}

func (pk *PK) Algo() string {
	return pk.algo.Algo()
}

func (sk *SK) Algo() string {
	return sk.algo.Algo()
}
