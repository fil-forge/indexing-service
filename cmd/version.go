package main

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/fil-forge/indexing-service/pkg/build"
)

var versionCmd = &cli.Command{
	Name:  "version",
	Usage: "Print the version of the indexing service, including the git revision.",
	Action: func(c *cli.Context) error {
		fmt.Printf("version: %s\n", build.Version)
		fmt.Printf("commit: %s\n", build.Commit)
		fmt.Printf("built at: %s\n", build.Date)
		fmt.Printf("built by: %s\n", build.BuiltBy)
		return nil
	},
}
