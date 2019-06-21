package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/trusch/pki/pkg/pki"
)

// caCmd represents the ca command
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "create a ca certificate",
	Long:  `This creates a CA certificate which can be used to sign other entities`,
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
		crt, key, err := ca.IssueCA(name, curve, rsaBits)
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
	issueCmd.AddCommand(caCmd)
}
