package pki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"errors"
)

func pemToDer(pemBytes []byte) ([]byte, string, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return nil, "", errors.New("no valid PEM data")
	}
	return b.Bytes, b.Type, nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
