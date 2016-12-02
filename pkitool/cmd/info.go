package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "show info about a certificate",
	Long:  `This parses a certificate and dumps infomation about it.`,
	Run: func(cmd *cobra.Command, args []string) {
		filename, _ := cmd.Flags().GetString("file")
		if filename == "" {
			if len(args) > 0 {
				filename = args[0]
			} else {
				log.Fatal("specify --file")
			}
		}
		bs, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}
		certBlock, _ := pem.Decode(bs)
		if certBlock == nil {
			log.Fatal("no valid PEM data")
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		const padding = 3
		w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', 0)
		fmt.Fprintf(w, "Name:\t %s\n", cert.Subject.CommonName)
		switch cert.ExtKeyUsage[0] {
		case x509.ExtKeyUsageClientAuth:
			{
				fmt.Fprintf(w, "Type:\t client\n")
			}
		case x509.ExtKeyUsageServerAuth:
			{
				fmt.Fprintf(w, "Type:\t server\n")
			}
		}
		fmt.Fprintf(w, "Not before:\t %s\n", cert.NotBefore.String())
		fmt.Fprintf(w, "Not after:\t %s\n", cert.NotAfter.String())
		fmt.Fprintf(w, "Is CA:\t %v\n", cert.IsCA)
		w.Flush()
	},
}

func init() {
	RootCmd.AddCommand(infoCmd)
	infoCmd.Flags().StringP("file", "f", "", "certificate file")
}
