package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/trusch/pki"
)

var cfgFile string

var RootCmd = &cobra.Command{
	Use:   "pkitool",
	Short: "a commandline tool to manage pki's",
	Long:  `This tools allows you to quickly setup public key infrastructures.`,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringP("pki", "p", "./pki", "pki directory")
	RootCmd.PersistentFlags().StringP("curve", "c", "", "elliptic curve to use (P521, P384, P256 or P224)")
	RootCmd.PersistentFlags().IntP("rsabits", "r", 2048, "RSA key size (4096, 2048 or 1024)")
}

func loadEntity(cmd *cobra.Command, name string) *pki.Entity {
	dir, _ := cmd.Flags().GetString("pki")
	entity, err := pki.NewEntityFromFile(filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key"))
	if err != nil {
		log.Fatal(err)
	}
	return entity
}

func saveEntity(cmd *cobra.Command, name string, entity *pki.Entity) {
	dir, _ := cmd.Flags().GetString("pki")
	cert, err := entity.GetCertAsPEM()
	if err != nil {
		log.Fatal(err)
	}
	key, err := entity.GetKeyAsPEM()
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(filepath.Join(dir, name+".crt"), cert, 0655)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(filepath.Join(dir, name+".key"), key, 0600)
	if err != nil {
		log.Fatal(err)
	}
}

func loadCA(cmd *cobra.Command) *pki.CA {
	dir, _ := cmd.Flags().GetString("pki")
	entity := loadEntity(cmd, "ca")
	serial, err := os.Open(filepath.Join(dir, "serial"))
	if err != nil {
		log.Fatal(err)
	}
	defer serial.Close()
	decoder := json.NewDecoder(serial)
	num := &big.Int{}
	err = decoder.Decode(num)
	if err != nil {
		log.Fatal(err)
	}
	return &pki.CA{
		Entity:     entity,
		NextSerial: num,
	}
}

func saveCA(cmd *cobra.Command, ca *pki.CA) {
	dir, _ := cmd.Flags().GetString("pki")
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		log.Fatal(err)
	}
	saveEntity(cmd, "ca", ca.Entity)
	f, err := os.Create(filepath.Join(dir, "serial"))
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	err = encoder.Encode(ca.NextSerial)
	if err != nil {
		log.Fatal(err)
	}
}
