package main

import (
	"flag"
	"log"
	"net/http"
	"strings"

	"gopkg.in/mgo.v2"

	"github.com/gorilla/mux"
	"github.com/trusch/jwtd/jwt"
)

var rootCaCert = flag.String("root-ca-cert", "/etc/pkid/ca.crt", "root ca certificate")
var rootCaKey = flag.String("root-ca-key", "/etc/pkid/ca.key", "root ca key")
var rootCaSerial = flag.String("root-ca-serial", "/etc/pkid/ca.serial", "root ca serial")
var jwtdCertFile = flag.String("jwtd-cert", "/etc/pkid/jwtd.crt", "jwtd certificate")
var listenAddr = flag.String("listen", ":443", "listen address")
var dbAddr = flag.String("db", "mongo", "mongo address")

var jwtdCert interface{}

var session *mgo.Session

func init() {
	flag.Parse()
	key, err := jwt.LoadPublicKey(*jwtdCertFile)
	if err != nil {
		log.Fatal(err)
	}
	jwtdCert = key
	s, err := mgo.Dial(*dbAddr)
	if err != nil {
		log.Fatal(err)
	}
	session = s
}

type Entry struct {
	ID    string
	Value string
}

func AuthWrapper(handler func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		token := parts[1]
		claims, err := jwt.ValidateToken(token, jwtdCert)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		prefix_, claimExists := claims["subject"]
		prefix, claimIsString := prefix_.(string)
		if !claimExists || !claimIsString || !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func getPrivateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	caId := vars["caId"]
	entityId := vars["entityId"]
	typ := vars["type"]
	if entityId == "ca" {
		ca, err := GetOrCreateCA(caId)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Write([]byte(ca.Key))
		return
	}
	entity, err := GetOrCreateEntity(caId, entityId, typ)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.Write([]byte(entity.Key))
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/private/{caId}/{type}/{entityId}", AuthWrapper(getPrivateHandler))
	log.Fatal(http.ListenAndServeTLS(*listenAddr, *rootCaCert, *rootCaKey, r))
}
