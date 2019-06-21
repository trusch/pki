package pki

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSelfSignedRSA(t *testing.T) {
	cert, key, err := GenerateCert(nil, "my-cert", "", 10*365*24*time.Hour, false, 2048, "", x509.ExtKeyUsageServerAuth)
	assert.NotEmpty(t, cert)
	assert.NotEmpty(t, key)
	assert.Nil(t, err)
}

func TestGenerateSelfSignedECDSA(t *testing.T) {
	cert, key, err := GenerateCert(nil, "my-cert", "", 10*365*24*time.Hour, false, 0, "P521", x509.ExtKeyUsageServerAuth)
	assert.NotEmpty(t, cert)
	assert.NotEmpty(t, key)
	assert.Nil(t, err)
}
