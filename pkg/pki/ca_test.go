package pki

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCA(t *testing.T) {
	_, err := NewSelfSignedCA("test-ca", "P521", 0)
	assert.Nil(t, err)
}

func TestIssueing(t *testing.T) {
	ca, err := NewSelfSignedCA("test-ca", "P521", 0)

	serverCrt, serverKey, err := ca.IssueServer("my-server", "P521", 0)
	assert.Nil(t, err)
	assert.NotEmpty(t, serverCrt)
	assert.NotEmpty(t, serverKey)

	clientCrt, clientKey, err := ca.IssueClient("my-client", "P521", 0)
	assert.Nil(t, err)
	assert.NotEmpty(t, clientCrt)
	assert.NotEmpty(t, clientKey)

	caCrt, caKey, err := ca.IssueCA("my-ca", "P521", 0)
	assert.Nil(t, err)
	assert.NotEmpty(t, caCrt)
	assert.NotEmpty(t, caKey)
}

func TestSubCA(t *testing.T) {
	ca, _ := NewSelfSignedCA("test-ca", "P521", 0)
	caCrt, caKey, _ := ca.IssueCA("my-ca", "P521", 0)
	subCA, err := NewCA(caCrt, caKey, big.NewInt(1))
	assert.Nil(t, err)
	clientCrt, clientKey, err := subCA.IssueClient("my-client", "P521", 0)
	assert.Nil(t, err)
	assert.NotEmpty(t, clientCrt)
	assert.NotEmpty(t, clientKey)
}
