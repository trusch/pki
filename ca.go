package pki

import (
	"crypto/x509"
	"math/big"
	"time"
)

// CA is a certificate key pair which is able to issue new client-, server- and ca-certificates
type CA struct {
	*Entity
	NextSerial *big.Int
}

// IssueClient issues a new client certificate
// curve can be one of:
// * P224
// * P256
// * P384
// * P521
// rsaBits should be one of
// * 0 (if curve is specified)
// * 1024
// * 2048
// * 4096
func (ca *CA) IssueClient(name, curve string, rsaBits int) (cert, key []byte, err error) {
	return GenerateCert(ca, name, "", 10*365*24*time.Hour, false, rsaBits, curve, x509.ExtKeyUsageClientAuth)
}

// IssueServer issues a new server certificate
// curve can be one of:
// * P224
// * P256
// * P384
// * P521
// rsaBits should be one of
// * 0 (if curve is specified)
// * 1024
// * 2048
// * 4096
func (ca *CA) IssueServer(name, curve string, rsaBits int) (cert, key []byte, err error) {
	return GenerateCert(ca, name, "", 10*365*24*time.Hour, false, rsaBits, curve, x509.ExtKeyUsageServerAuth)
}

// IssueCA issues a new ca certificate
// curve can be one of:
// * P224
// * P256
// * P384
// * P521
// rsaBits should be one of
// * 0 (if curve is specified)
// * 1024
// * 2048
// * 4096
func (ca *CA) IssueCA(name, curve string, rsaBits int) (cert, key []byte, err error) {
	return GenerateCert(ca, name, "", 10*365*24*time.Hour, true, rsaBits, curve, x509.ExtKeyUsageAny)
}

// GetNextSerial returns the next free serial number and increases the internal value
func (ca *CA) GetNextSerial() *big.Int {
	if ca.NextSerial == nil {
		return nil
	}
	next := &big.Int{}
	next.Set(ca.NextSerial)
	ca.NextSerial.Add(ca.NextSerial, big.NewInt(1))
	return next
}

// NewCA creates a new CA from a key/cert pair and a nextSerial number
func NewCA(certPem, keyPem []byte, nextSerial *big.Int) (*CA, error) {
	entity, err := NewEntityFromPEM(certPem, keyPem)
	if err != nil {
		return nil, err
	}
	return &CA{
		Entity:     entity,
		NextSerial: nextSerial,
	}, nil
}

// NewSelfSignedCA creates a new self-signed CA
// // curve can be one of:
// * P224
// * P256
// * P384
// * P521
// rsaBits should be one of
// * 0 (if curve is specified)
// * 1024
// * 2048
// * 4096
func NewSelfSignedCA(caID string, curve string, rsaBits int) (*CA, error) {
	cert, key, err := GenerateCert(nil, caID, "", 10*365*24*time.Hour, true, rsaBits, curve, x509.ExtKeyUsageAny)
	if err != nil {
		return nil, err
	}
	return NewCA(cert, key, big.NewInt(1))
}
