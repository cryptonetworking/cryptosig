package cryptosig

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"github.com/itsabgr/go-handy"
	"github.com/vmihailenco/msgpack/v5"
)

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
type SecretKey interface {
	encoding.BinaryUnmarshaler
	UnsafeMarshalBinary() ([]byte, error)
	Algo() string
	Sign(msg []byte) Signature
	Unwrap() any
	PublicKey() PublicKey
}
type PublicKey interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Algo() string
	Verify(Signature, []byte) error
	Unwrap() any
}

type Signature interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	Algo() string
	Verify(PublicKey, []byte) error
	Unwrap() any
}

var regSigAlgo = make(map[string]SigningAlgo[any, any, any])

type s struct {
	algo SigningAlgo[any, any, any]
	sk   any
}

type p struct {
	algo SigningAlgo[any, any, any]
	pk   any
}
type si struct {
	algo SigningAlgo[any, any, any]
	sig  any
}

func (sig *si) MarshalBinary() ([]byte, error) {
	return sig.encode(), nil
}

func (sk *s) MarshalBinary() ([]byte, error) {
	panic("marshaling secret-key is not allowed and can cause security problems")
}

func (pk *p) MarshalBinary() ([]byte, error) {
	return pk.encode(), nil
}

func (sig *si) UnmarshalBinary(data []byte) error {
	sig2, err := UnmarshalBinarySignature(data)
	if err == nil {
		*sig = *(sig2.(*si))
	}
	return err
}
func (sk *s) UnmarshalBinary(data []byte) error {
	sk2, err := UnmarshalBinarySecretKey(data)
	if err == nil {
		*sk = *(sk2.(*s))
	}
	return err
}
func (pk *p) UnmarshalBinary(data []byte) error {
	pk2, err := UnmarshalBinaryPublicKey(data)
	if err == nil {
		*pk = *(pk2.(*p))
	}
	return err
}

func (sig *si) Unwrap() any {
	return sig.sig
}
func (pk *p) Unwrap() any {
	return pk.pk
}
func (sk *s) Unwrap() any {
	return sk.sk
}
func RegisterSigAlgo(algo SigningAlgo[any, any, any]) {
	regSigAlgo[algo.Algo()] = algo
}

func (sk *s) Sign(msg []byte) Signature {
	algo := sk.algo
	signature := algo.Sign(sk.sk, msg)
	return &si{algo, signature}
}

func New(algo string) SecretKey {
	algorithm := regSigAlgo[algo]
	secKey := algorithm.New()
	return &s{algorithm, secKey}
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

func (sk *s) UnsafeMarshalBinary() ([]byte, error) {
	algo := sk.algo
	name := algo.Algo()
	b := algo.MarshalBinarySecretKey(sk.sk)
	return encode(name, 1, b), nil
}
func (sig *si) encode() []byte {
	algo := sig.algo
	name := algo.Algo()
	b := algo.MarshalBinarySignature(sig.sig)
	return encode(name, 3, b)
}
func (pk *p) encode() []byte {
	algo := pk.algo
	name := algo.Algo()
	b := algo.MarshalBinaryPublicKey(pk.pk)
	return encode(name, 2, b)
}

func UnmarshalBinarySecretKey(b []byte) (SecretKey, error) {
	name, kind, p, err := decode(b)
	if err != nil {
		return nil, err
	}
	if kind != 1 {
		return nil, errors.New("not s")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return nil, fmt.Errorf("unsupported algorithm %q", name)
	}
	secKey, err := algo.UnmarshalBinarySecretKey(p)
	if err != nil {
		return nil, err
	}
	return &s{algo, secKey}, nil
}
func UnmarshalBinaryPublicKey(b []byte) (PublicKey, error) {
	name, kind, bin, err := decode(b)
	if err != nil {
		return nil, err
	}
	if kind != 2 {
		return nil, errors.New("not p")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return nil, fmt.Errorf("unsupported algorithm %q", name)
	}
	pubKey, err := algo.UnmarshalBinaryPublicKey(bin)
	if err != nil {
		return nil, err
	}
	return &p{algo, pubKey}, nil
}
func UnmarshalBinarySignature(b []byte) (Signature, error) {
	name, kind, p, err := decode(b)
	if err != nil {
		return nil, err
	}
	if kind != 3 {
		return nil, errors.New("not si")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return nil, fmt.Errorf("unsupported algorithm %q", name)
	}
	signature, err := algo.UnmarshalBinarySignature(p)
	if err != nil {
		return nil, err
	}
	return &si{algo, signature}, nil
}
func (sk *s) PublicKey() PublicKey {
	algo := sk.algo
	return &p{algo, algo.Derive(sk.sk)}
}
func (pk *p) Verify(sig Signature, msg []byte) error {
	algo := pk.algo
	return algo.Verify(sig.Unwrap(), pk.pk, msg)
}
func (sig *si) Verify(pk PublicKey, msg []byte) error {
	algo := sig.algo
	return algo.Verify(sig.sig, pk.Unwrap(), msg)
}

func (sig *si) Algo() string {
	return sig.algo.Algo()
}

func (pk *p) Algo() string {
	return pk.algo.Algo()
}

func (sk *s) Algo() string {
	return sk.algo.Algo()
}
