package cryptosig

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsabgr/go-handy"
	"github.com/valyala/fastjson"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/bcrypt"
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
	encoding.TextUnmarshaler
	UnsafeMarshalBinary() ([]byte, error)
	UnsafeMarshalText() ([]byte, error)
	Algo() string
	Sign(msg []byte) Signature
	Unwrap() any
	PublicKey() PublicKey
}
type HashedPublicKey interface {
	Equal(PublicKey) bool
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	json.Marshaler
	json.Unmarshaler
}
type PublicKey interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	json.Marshaler
	json.Unmarshaler
	Algo() string
	Verify(Signature, []byte) error
	Unwrap() any
	Fork() HashedPublicKey
}
type Signature interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	json.Marshaler
	json.Unmarshaler
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
type pp struct {
	b []byte
}

func (p *pp) Equal(pulicKey PublicKey) bool {
	b, err := pulicKey.MarshalBinary()
	handy.Throw(err)
	return bcrypt.CompareHashAndPassword(p.b, b) == nil
}

func (p *pp) MarshalBinary() (data []byte, err error) {
	return p.b, nil
}

func (p *pp) MarshalJSON() (data []byte, err error) {
	return []byte(fmt.Sprintf(`{"pub":"%s"}`, hex.EncodeToString(p.b))), nil
}

func (p *pp) UnmarshalBinary(data []byte) error {
	_, err := bcrypt.Cost(data)
	if err != nil {
		return err
	}
	p.b = data
	return nil
}

func (p *pp) UnmarshalJSON(data []byte) error {
	x, err := hex.DecodeString(fastjson.GetString(data, "pub"))
	if err != nil {
		return err
	}
	return p.UnmarshalBinary(x)
}

func (pk *p) Fork() HashedPublicKey {
	b, err := bcrypt.GenerateFromPassword(pk.encode(), bcrypt.DefaultCost)
	handy.Throw(err)
	return &pp{b}
}

type si struct {
	algo SigningAlgo[any, any, any]
	sig  any
}

func (sig *si) MarshalBinary() ([]byte, error) {
	return sig.encode(), nil
}

func (sig *si) MarshalJSON() ([]byte, error) {
	algo := sig.algo
	name := algo.Algo()
	b := algo.MarshalBinarySignature(sig.sig)
	return []byte(fmt.Sprintf(`{"sig":"%s","algo":"%s"}`, hex.EncodeToString(b), name)), nil
}

func (sk *s) MarshalBinary() ([]byte, error) {
	panic("marshaling secret-key is not allowed and can cause security problems")
}

func (sk *s) MarshalJSON() ([]byte, error) {
	panic("marshaling secret-key is not allowed and can cause security problems")
}

func (pk *p) MarshalBinary() ([]byte, error) {
	return pk.encode(), nil
}

func (pk *p) MarshalJSON() ([]byte, error) {
	algo := pk.algo
	name := algo.Algo()
	b := algo.MarshalBinaryPublicKey(pk.pk)
	return []byte(fmt.Sprintf(`{"pub":"%s","algo":"%s"}`, hex.EncodeToString(b), name)), nil
}

func (sig *si) UnmarshalBinary(data []byte) error {
	sig2, err := UnmarshalBinarySignature(data)
	if err == nil {
		*sig = *(sig2.(*si))
	}
	return err
}

func (sig *si) UnmarshalJSON(data []byte) error {
	x, err := hex.DecodeString(fastjson.GetString(data, "sig"))
	if err != nil {
		return err
	}
	name := fastjson.GetString(data, "algo")
	algo, found := regSigAlgo[name]
	if !found {
		return fmt.Errorf("unsupported algorithm %q", name)
	}
	signature, err := algo.UnmarshalBinarySignature(x)
	if err != nil {
		return err
	}
	sig.algo = algo
	sig.sig = signature
	return nil
}

func (pk *p) UnmarshalJSON(data []byte) error {
	x, err := hex.DecodeString(fastjson.GetString(data, "pub"))
	if err != nil {
		return err
	}
	name := fastjson.GetString(data, "algo")
	algo, found := regSigAlgo[name]
	if !found {
		return fmt.Errorf("unsupported algorithm %q", name)
	}
	public, err := algo.UnmarshalBinaryPublicKey(x)
	if err != nil {
		return err
	}
	pk.algo = algo
	pk.pk = public
	return nil
}

func (sk *s) UnmarshalBinary(data []byte) error {
	sk2, err := UnmarshalBinarySecretKey(data)
	if err == nil {
		*sk = *(sk2.(*s))
	}
	return err
}
func (sk *s) UnmarshalText(data []byte) error {
	x, err := hex.DecodeString(string(data))
	if err != nil {
		return err
	}
	return sk.UnmarshalBinary(x)
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
func (sk *s) Sign(msg []byte) Signature {
	algo := sk.algo
	signature := algo.Sign(sk.sk, msg)
	return &si{algo, signature}
}

func GenerateSecretKey(algo string) SecretKey {
	algorithm := regSigAlgo[algo]
	secKey := algorithm.New()
	return &s{algorithm, secKey}
}
func NewSecretKey() SecretKey {
	return &s{}
}

func NewPublicKey() PublicKey {
	return &p{}
}

func NewHashedPublicKey() HashedPublicKey {
	return &pp{}
}

func NewSignature() Signature {
	return &si{}
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

func (sk *s) UnsafeMarshalText() ([]byte, error) {
	algo := sk.algo
	name := algo.Algo()
	b := algo.MarshalBinarySecretKey(sk.sk)
	return []byte(hex.EncodeToString(encode(name, 1, b))), nil
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

func UnmarshalTextSecretKey(b []byte) (SecretKey, error) {
	x, err := hex.DecodeString(string(b))
	if err != nil {
		return nil, err
	}
	return UnmarshalBinarySecretKey(x)
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
