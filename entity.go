package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

type Entity struct {
	Cert      *x509.Certificate
	Key       interface{}
	Algorithm x509.PublicKeyAlgorithm
}

func NewEntityFromDER(certDer, keyDer []byte, algo x509.PublicKeyAlgorithm) (*Entity, error) {
	entity := &Entity{Algorithm: algo}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, err
	}
	entity.Cert = cert
	switch algo {
	case x509.RSA:
		{
			k, err := x509.ParsePKCS1PrivateKey(keyDer)
			if err != nil {
				return nil, err
			}
			entity.Key = k
		}
	case x509.ECDSA:
		{
			k, err := x509.ParseECPrivateKey(keyDer)
			if err != nil {
				return nil, err
			}
			entity.Key = k
		}
	default:
		{
			return nil, errors.New("unknown private key type")
		}
	}
	return entity, nil
}

func NewEntityFromPEM(cert []byte, key []byte) (*Entity, error) {
	keyBlock, _ := pem.Decode(key)
	if keyBlock == nil {
		return nil, errors.New("no valid PEM data")
	}
	certBlock, _ := pem.Decode(cert)
	if certBlock == nil {
		return nil, errors.New("no valid PEM data")
	}
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		{
			return NewEntityFromDER(certBlock.Bytes, keyBlock.Bytes, x509.RSA)
		}
	case "EC PRIVATE KEY":
		{
			return NewEntityFromDER(certBlock.Bytes, keyBlock.Bytes, x509.ECDSA)
		}
	}
	return nil, errors.New("unknown private key type")
}

func NewEntityFromFile(cert, key string) (*Entity, error) {
	keyBs, err := ioutil.ReadFile(key)
	if err != nil {
		return nil, err
	}
	certBs, err := ioutil.ReadFile(cert)
	if err != nil {
		return nil, err
	}
	return NewEntityFromPEM(certBs, keyBs)
}

func (entity *Entity) GetCertAsDER() ([]byte, error) {
	return entity.Cert.Raw, nil
}

func (entity *Entity) GetKeyAsDER() ([]byte, error) {
	switch k := entity.Key.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		return x509.MarshalECPrivateKey(k)
	}
	return nil, errors.New("unknown private key")
}

func (entity *Entity) GetCertAsPEM() ([]byte, error) {
	der, err := entity.GetCertAsDER()
	if err != nil {
		return nil, err
	}
	out := &bytes.Buffer{}
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (entity *Entity) GetKeyAsPEM() ([]byte, error) {
	der, err := entity.GetKeyAsDER()
	if err != nil {
		return nil, err
	}
	out := &bytes.Buffer{}
	switch entity.Key.(type) {
	case *rsa.PrivateKey:
		err = pem.Encode(out, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	case *ecdsa.PrivateKey:
		err = pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
