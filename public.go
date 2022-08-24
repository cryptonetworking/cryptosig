package cryptosig

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/itsabgr/go-handy"
	"github.com/valyala/fastjson"
	"golang.org/x/crypto/bcrypt"
)

type PublicKey struct {
	algo SigningAlgo[any, any, any]
	pk   any
}

func (pk *PublicKey) Fork() HashedPublicKey {
	b, err := bcrypt.GenerateFromPassword(pk.encode(), bcrypt.DefaultCost)
	handy.Throw(err)
	return HashedPublicKey{b}
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.encode(), nil
}

func (pk *PublicKey) MarshalJSON() ([]byte, error) {
	algo := pk.algo
	name := algo.Algo()
	b := algo.MarshalBinaryPublicKey(pk.pk)
	return []byte(fmt.Sprintf(`{"pub":"%s","algo":"%s"}`, hex.EncodeToString(b), name)), nil
}

func (pk *PublicKey) UnmarshalJSON(data []byte) error {
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

func (pk *PublicKey) UnmarshalBinary(b []byte) error {
	name, kind, bin, err := decode(b)
	if err != nil {
		return err
	}
	if kind != 2 {
		return errors.New("not PublicKey")
	}
	algo, found := regSigAlgo[name]
	if !found {
		return fmt.Errorf("unsupported algorithm %q", name)
	}
	pubKey, err := algo.UnmarshalBinaryPublicKey(bin)
	if err != nil {
		return err
	}
	pk.algo = algo
	pk.pk = pubKey
	return nil
}

func (pk *PublicKey) Unwrap() any {
	return pk.pk
}

func (pk *PublicKey) encode() []byte {
	algo := pk.algo
	name := algo.Algo()
	b := algo.MarshalBinaryPublicKey(pk.pk)
	return encode(name, 2, b)
}

func (pk *PublicKey) Algo() string {
	return pk.algo.Algo()
}

func (pk *PublicKey) Verify(sig *Signature, msg []byte) error {
	algo := pk.algo
	return algo.Verify(sig.Unwrap(), pk.pk, msg)
}
