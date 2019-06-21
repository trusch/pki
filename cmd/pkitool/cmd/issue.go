package cmd

import (
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// issueCmd represents the issue command
var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "toplevel command for issueing certificates",
	Long:  `Here you can issue different types of certificates.`,
}

func init() {
	RootCmd.AddCommand(issueCmd)
	issueCmd.PersistentFlags().StringP("name", "n", "", "common name")
}

func checkSafeIssue(cmd *cobra.Command, name string) {
	dir, _ := cmd.Flags().GetString("pki")
	f, err := os.Open(filepath.Join(dir, name+".crt"))
	if err == nil {
		log.Fatal("issue candidate already exists")
		f.Close()
	}
}
