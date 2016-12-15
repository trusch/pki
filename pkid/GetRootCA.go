package main

import (
	"encoding/json"
	"io/ioutil"
	"math/big"

	"github.com/trusch/pki"

	"gopkg.in/mgo.v2/bson"
)

const ROOT_CA = "root"

type CA struct {
	ID     string
	Cert   string
	Key    string
	Serial string
}

func (ca *CA) ToPKI() (*pki.CA, error) {
	num := &big.Int{}
	err := json.Unmarshal([]byte(ca.Serial), num)
	if err != nil {
		return nil, err
	}
	return pki.NewCA([]byte(ca.Cert), []byte(ca.Key), num)
}

func (ca *CA) Save() error {
	c := session.DB("pkid").C("ca")
	_, err := c.Upsert(bson.M{"id": ca.ID}, ca)
	return err
}

func GetRootCA() (*CA, error) {
	ca := &CA{}
	c := session.DB("pkid").C("ca")
	err := c.Find(bson.M{"id": ROOT_CA}).One(ca)
	if err != nil {
		certBs, e := ioutil.ReadFile(*rootCaCert)
		if e != nil {
			return nil, e
		}
		keyBs, e := ioutil.ReadFile(*rootCaKey)
		if e != nil {
			return nil, e
		}
		serialBs, e := ioutil.ReadFile(*rootCaSerial)
		if e != nil {
			serialBs = []byte{'1'}
		}
		ca = &CA{ROOT_CA, string(certBs), string(keyBs), string(serialBs)}
		err := ca.Save()
		if err != nil {
			return nil, err
		}
	}
	return ca, nil
}

func GetCA(id string) (*CA, error) {
	ca := &CA{}
	c := session.DB("pkid").C("ca")
	err := c.Find(bson.M{"id": id}).One(ca)
	if err != nil {
		return nil, err
	}
	return ca, nil
}
