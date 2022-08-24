package cryptosig

import (
	"errors"
	"github.com/itsabgr/go-handy"
	"golang.org/x/crypto/bcrypt"
)

type HashedPublicKey struct {
	b []byte
}

func (pk *PublicKey) Fork() *HashedPublicKey {
	text, err := pk.MarshalText()
	if err != nil {
		panic(err)
	}
	b, err := bcrypt.GenerateFromPassword(text, bcrypt.DefaultCost)
	handy.Throw(err)
	return &HashedPublicKey{b}
}

func (p *HashedPublicKey) Equal(publicKey *PublicKey) bool {
	text, err := publicKey.MarshalText()
	handy.Throw(err)
	return bcrypt.CompareHashAndPassword(p.b, text) == nil
}

func (p *HashedPublicKey) MarshalText() (text []byte, err error) {
	return encode("pub", "", p.b), nil
}
func (p *HashedPublicKey) UnmarshalText(text []byte) error {
	kind, algo, b, err := decode(text)
	if err != nil {
		return err
	}
	if kind != "pub" || algo != "" {
		return errors.New("not HashedPublicKey")
	}
	_, err = bcrypt.Cost(b)
	if err != nil {
		return err
	}
	p.b = b
	return nil
}
