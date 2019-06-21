package main

import (
	"errors"

	"gopkg.in/mgo.v2/bson"
)

type Entity struct {
	CA   string
	ID   string
	Cert string
	Key  string
	Type string
}

func (entity *Entity) Save() error {
	c := session.DB("pkid").C("entities")
	_, err := c.Upsert(bson.M{"caId": entity.CA, "id": entity.ID}, entity)
	return err
}
func GetOrCreateEntity(caId, entityId, typ string) (*Entity, error) {
	c := session.DB("pkid").C("entities")
	entity := &Entity{}
	err := c.Find(bson.M{"ca": caId, "id": entityId, "type": typ}).One(entity)
	if err != nil {
		ca, err := GetOrCreateCA(caId)
		if err != nil {
			return nil, err
		}
		var (
			cert, key []byte
		)
		ca_, err := ca.ToPKI()
		if err != nil {
			return nil, err
		}
		switch typ {
		case "server":
			cert, key, err = ca_.IssueServer(entityId, "", 2048)
		case "client":
			cert, key, err = ca_.IssueClient(entityId, "", 2048)
		default:
			return nil, errors.New("unsupported type")
		}
		if err != nil {
			return nil, err
		}
		entity = &Entity{caId, entityId, string(cert), string(key), typ}
		err = entity.Save()
		if err != nil {
			return nil, err
		}
	}
	return entity, nil

}
