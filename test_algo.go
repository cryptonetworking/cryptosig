package cryptosig

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

func TestAlgo(algo SigningAlgo[any, any, any]) error {
	Algo := algo.Algo()
	RegisterSigAlgo(algo)
	sk := GenerateSecretKey(Algo)
	if sk.Algo() != Algo {
		return errors.New("non-equal algorithm name")
	}
	msg := make([]byte, 512)
	_, err := io.ReadFull(rand.Reader, msg)
	if err != nil {
		panic(err)
	}
	b, err := sk.Sign(msg).MarshalText()
	if err != nil {
		return err
	}
	sig := new(Signature)
	err = sig.UnmarshalText(b)
	if err != nil {
		return err
	}
	if sig.Algo() != Algo {
		return errors.New("non-equal algorithm name")
	}
	b, err = sk.UnsafeUnmarshalText()
	if err != nil {
		return err
	}
	sk = new(SecretKey)
	err = sk.UnmarshalText(b)
	if err != nil {
		return err
	}
	if sk.Algo() != Algo {
		return err
	}
	b, err = sk.PublicKey().MarshalText()
	if err != nil {
		return err
	}
	pk := new(PublicKey)
	err = pk.UnmarshalText(b)
	if err != nil {
		return err
	}
	if pk.Algo() != Algo {
		return errors.New("non-equal algorithm name")
	}
	err = sig.Verify(pk, msg)
	if err != nil {
		return err
	}
	err = pk.Verify(sig, msg)
	if err != nil {
		return err
	}
	sk2 := GenerateSecretKey(Algo)
	err = sk2.PublicKey().Verify(sig, msg)
	if err == nil {
		return errors.New("algorithm failed")
	}
	sig2 := sk2.Sign(msg)
	err = pk.Verify(sig2, msg)
	if err == nil {
		return errors.New("algorithm failed")
	}
	sk = GenerateSecretKey(Algo)
	cert := sk.TLS()
	if cert != nil {
		ln, err := tls.Listen("tcp", "localhost:0", &tls.Config{
			Certificates:       []tls.Certificate{*cert},
			InsecureSkipVerify: true,
		})
		if err != nil {
			return err
		}
		defer ln.Close()
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
			writer.Write([]byte("hello world"))
		})
		go http.Serve(ln, mux)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			fmt.Sprintf("https://%s/", ln.Addr().String()),
			nil)
		if err != nil {
			panic(err)
		}
		c := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}}
		defer c.CloseIdleConnections()
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		if !resp.TLS.HandshakeComplete {
			panic(errors.New("cryptosig: test algo: tls error"))
		}
	}
	return nil
}
