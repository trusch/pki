package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/trusch/pki/pkg/pki"
)

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "this issues a client certificate",
	Long:  `This issues a client certificate usable for authenticating clients on servers.`,
	Run: func(cmd *cobra.Command, args []string) {
		ca := loadCA(cmd)
		name, _ := cmd.Flags().GetString("name")
		if name == "" {
			if len(args) > 0 {
				name = args[0]
			} else {
				log.Fatal("specify --name")
			}
		}
		checkSafeIssue(cmd, name)
		curve, _ := cmd.Flags().GetString("curve")
		rsaBits, _ := cmd.Flags().GetInt("rsabits")
		if rsaBits != 0 {
			curve = ""
		}
		crt, key, err := ca.IssueClient(name, curve, rsaBits)
		if err != nil {
			log.Fatal(err)
		}
		entity, err := pki.NewEntityFromPEM(crt, key)
		if err != nil {
			log.Fatal(err)
		}
		saveEntity(cmd, name, entity)
		saveCA(cmd, ca)
	},
}

func init() {
	issueCmd.AddCommand(clientCmd)
}
