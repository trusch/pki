package main

import (
	"log"

	"github.com/trusch/pki/cmd/pkitool/cmd"
)

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	cmd.Execute()
}
