package cmd

import (
	"io"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/trusch/pki"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "init a new CA",
	Long:  `This initializes a new CA by creating a self signed CA certificate.`,
	Run: func(cmd *cobra.Command, args []string) {
		checkSafeInit(cmd)
		curve, _ := cmd.Flags().GetString("curve")
		rsaBits, _ := cmd.Flags().GetInt("rsabits")
		if rsaBits != 0 {
			curve = ""
		}
		ca, err := pki.NewSelfSignedCA(curve, rsaBits)
		if err != nil {
			log.Fatal(err)
		}
		saveCA(cmd, ca)
	},
}

func checkSafeInit(cmd *cobra.Command) {
	dir, _ := cmd.Flags().GetString("pki")
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	defer f.Close()
	_, err = f.Readdirnames(1) // Or f.Readdir(1)
	if err == io.EOF {
		return
	}
	log.Fatal("no safe init possible (target directory is not empty)")
}

func init() {
	RootCmd.AddCommand(initCmd)
}
