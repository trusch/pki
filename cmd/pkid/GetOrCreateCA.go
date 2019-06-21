package main

import "encoding/json"

func GetOrCreateCA(caId string) (*CA, error) {
	ca, err := GetCA(caId)
	if err != nil {
		rootCa_, e := GetRootCA()
		if e != nil {
			return nil, e
		}
		rootCa, e := rootCa_.ToPKI()
		if e != nil {
			return nil, e
		}
		caCert, caKey, e := rootCa.IssueCA(caId, "", 2048)
		if e != nil {
			return nil, e
		}
		ca = &CA{
			ID:     caId,
			Cert:   string(caCert),
			Key:    string(caKey),
			Serial: "1",
		}
		e = ca.Save()
		if e != nil {
			return nil, e
		}
		bs, _ := json.Marshal(rootCa.NextSerial)
		rootCa_.Serial = string(bs)
		e = rootCa_.Save()
		if e != nil {
			return nil, e
		}
	}
	return ca, nil
}
