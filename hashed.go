package cryptosig

import (
	"encoding/hex"
	"fmt"
	"github.com/itsabgr/go-handy"
	"github.com/valyala/fastjson"
	"golang.org/x/crypto/bcrypt"
)

type HashedPublicKey struct {
	b []byte
}

func (p *HashedPublicKey) Equal(publicKey PublicKey) bool {
	b, err := publicKey.MarshalBinary()
	handy.Throw(err)
	return bcrypt.CompareHashAndPassword(p.b, b) == nil
}

func (p *HashedPublicKey) MarshalBinary() (data []byte, err error) {
	return p.b, nil
}

func (p *HashedPublicKey) MarshalJSON() (data []byte, err error) {
	return []byte(fmt.Sprintf(`{"pub":"%s"}`, hex.EncodeToString(p.b))), nil
}

func (p *HashedPublicKey) UnmarshalBinary(data []byte) error {
	_, err := bcrypt.Cost(data)
	if err != nil {
		return err
	}
	p.b = data
	return nil
}

func (p *HashedPublicKey) UnmarshalJSON(data []byte) error {
	x, err := hex.DecodeString(fastjson.GetString(data, "pub"))
	if err != nil {
		return err
	}
	return p.UnmarshalBinary(x)
}
