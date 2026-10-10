// Command whosent explains a Mandatum delegation chain: who sent this agent,
// and what is it still allowed to do.
package main

import (
	"os"

	"github.com/kanywst/whosent/internal/cmd"
)

func main() { os.Exit(cmd.Execute()) }
