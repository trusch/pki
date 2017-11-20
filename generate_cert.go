package pki

// mainly copied from https://golang.org/src/crypto/tls/generate_cert.go

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			return nil
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func GenerateCert(ca *CA, name string, validFrom string, validFor time.Duration, isCA bool, rsaBits int, ecdsaCurve string, usage x509.ExtKeyUsage) (cert, key []byte, err error) {
	var priv interface{}
	switch ecdsaCurve {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, nil, fmt.Errorf("Unrecognized elliptic curve: %q", ecdsaCurve)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %s", err)
	}
	var notBefore time.Time
	if len(validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", validFrom)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to parse creation date: %s", err)
		}
	}

	notAfter := notBefore.Add(validFor)

	var serialNumber *big.Int
	if ca == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
		}
	} else {
		serialNumber = ca.GetNextSerial()
		if serialNumber == nil {
			serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
			serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate serial number: %s", err)
			}
		}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   name,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	signerCert := &template
	if ca != nil {
		signerCert = ca.Cert
	}
	signerKey := priv
	if ca != nil {
		signerKey = ca.Key
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, signerCert, publicKey(priv), signerKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create certificate: %s", err)
	}

	certOut := &bytes.Buffer{}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut := &bytes.Buffer{}
	pem.Encode(keyOut, pemBlockForKey(priv))
	return certOut.Bytes(), keyOut.Bytes(), nil
}
