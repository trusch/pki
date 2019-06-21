package cmd

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/trusch/pki/pkg/pki"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "this issues a server certificate",
	Long:  `This issues a server certificate usable for authenticating servers on clients.`,
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
		crt, key, err := ca.IssueServer(name, curve, rsaBits)
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
	issueCmd.AddCommand(serverCmd)
}
