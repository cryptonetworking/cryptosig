package cryptosig

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/valyala/fastjson"
)

type Signature struct {
	algo SigningAlgo[any, any, any]
	sig  any
}

func (sig *Signature) Unwrap() any {
	return sig.sig
}

func (sig *Signature) Verify(pk *PublicKey, msg []byte) error {
	algo := sig.algo
	return algo.Verify(sig.sig, pk.Unwrap(), msg)
}
func (sig *Signature) Algo() string {
	return sig.algo.Algo()
}

func (sig *Signature) MarshalBinary() ([]byte, error) {
	return sig.encode(), nil
}

func (sig *Signature) MarshalJSON() ([]byte, error) {
	algo := sig.algo
	name := algo.Algo()
	b := algo.MarshalBinarySignature(sig.sig)
	return []byte(fmt.Sprintf(`{"sig":"%s","algo":"%s"}`, hex.EncodeToString(b), name)), nil
}

func (sig *Signature) encode() []byte {
	algo := sig.algo
	name := algo.Algo()
	b := algo.MarshalBinarySignature(sig.sig)
	return encode(name, 3, b)
}
func (sig *Signature) UnmarshalBinary(b []byte) error {
	name, kind, p, err := decode(b)
	if err != nil {
		return err
	}
	if kind != 3 {
		return errors.New("not Signature")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return fmt.Errorf("unsupported algorithm %q", name)
	}
	signature, err := algo.UnmarshalBinarySignature(p)
	if err != nil {
		return err
	}
	sig.sig = signature
	sig.algo = algo
	return nil
}

func (sig *Signature) UnmarshalJSON(data []byte) error {
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
