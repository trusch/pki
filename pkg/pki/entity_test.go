package pki

import (
	"crypto/x509"
	"io/ioutil"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestEntityRSA(t *testing.T) {
	cert, key, err := GenerateCert(nil, "my-cert", "", 10*365*24*time.Hour, false, 2048, "", x509.ExtKeyUsageServerAuth)
	assert.NotEmpty(t, cert)
	assert.NotEmpty(t, key)
	assert.Nil(t, err)
	ioutil.WriteFile("/tmp/foo.crt", cert, 0755)
	ioutil.WriteFile("/tmp/foo.key", key, 0755)

	entity, err := NewEntityFromFile("/tmp/foo.crt", "/tmp/foo.key")
	assert.Nil(t, err)
	certPem, err := entity.GetCertAsPEM()
	assert.Nil(t, err)
	keyPem, err := entity.GetKeyAsPEM()
	assert.Nil(t, err)
	ioutil.WriteFile("/tmp/foo2.crt", certPem, 0755)
	ioutil.WriteFile("/tmp/foo2.key", keyPem, 0755)
	test1 := exec.Command("diff", "/tmp/foo.crt", "/tmp/foo2.crt")
	err = test1.Run()
	assert.Nil(t, err)
	test2 := exec.Command("diff", "/tmp/foo.crt", "/tmp/foo2.crt")
	err = test2.Run()
	assert.Nil(t, err)
}

func TestEntityEC(t *testing.T) {
	cert, key, err := GenerateCert(nil, "my-cert", "", 10*365*24*time.Hour, false, 0, "P521", x509.ExtKeyUsageServerAuth)
	assert.NotEmpty(t, cert)
	assert.NotEmpty(t, key)
	assert.Nil(t, err)
	ioutil.WriteFile("/tmp/foo.crt", cert, 0755)
	ioutil.WriteFile("/tmp/foo.key", key, 0755)

	entity, err := NewEntityFromFile("/tmp/foo.crt", "/tmp/foo.key")
	assert.Nil(t, err)
	certPem, err := entity.GetCertAsPEM()
	assert.Nil(t, err)
	keyPem, err := entity.GetKeyAsPEM()
	assert.Nil(t, err)
	ioutil.WriteFile("/tmp/foo2.crt", certPem, 0755)
	ioutil.WriteFile("/tmp/foo2.key", keyPem, 0755)
	test1 := exec.Command("diff", "/tmp/foo.crt", "/tmp/foo2.crt")
	err = test1.Run()
	assert.Nil(t, err)
	test2 := exec.Command("diff", "/tmp/foo.crt", "/tmp/foo2.crt")
	err = test2.Run()
	assert.Nil(t, err)
}
