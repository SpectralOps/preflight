package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/alecthomas/kong"
	"github.com/spectralops/preflight/pkg"
)

type VersionFlag string

var CLI struct {
	Version struct {
	} `cmd  help:"Print version information and quit"`

	Run struct {
		Hash string   `arg name:"hash|url" help:"Hash to verify. You can provide a list separated by a comma (,) and no space. Format: sha256=<hash>[,sha256=<hash2>,...], Or a URL to a flat file to fetch with a list of hashes, one per line. Format: https://example.com/file.txt"`
		Cmd  []string `arg optional name:"cmd" help:"Command to execute"`
	} `cmd help:"Verify and run a command"`

	Check struct {
		Hash string   `arg name:"hash|url" help:"Hash to verify. You can provide a list separated by a comma (,) and no space. Format: sha256=<hash>[,sha256=<hash2>,...], Or a URL to a flat file to fetch with a list of hashes, one per line. Format: https://example.com/file.txt"`
		Cmd  []string `arg optional name:"cmd" help:"Command to execute"`
	} `cmd help:"Verify a command"`

	Create struct {
		File   string `arg optional name:"file" help:"File to create hash for"`
		Digest string `optional name:"digest" enum:"sha256,sha1,md5," help:"Digest type: [sha256 | sha1 | md5]"`
	} `cmd help:"Create a hash digest for verifying later"`
}

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

//nolint
func main() {
	ctx := kong.Parse(&CLI)

	//nolint
	switch ctx.Command() {
	case "version":
		fmt.Printf("Preflight %v\n", version)
		fmt.Printf("Revision %v, date: %v\n", commit, date)
		os.Exit(0)
	}

	lookup, err := pkg.GetLookup()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	preflight := pkg.NewPreflight(lookup)

	switch ctx.Command() {
	case "run <hash|url>":
		// piping
		var fin io.Reader = os.Stdin
		s, err := ioutil.ReadAll(fin)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		err = preflight.ExecPiped(string(s), CLI.Run.Hash)
		if err != nil {
			os.Exit(1)
		}

	case "run <hash|url> <cmd>":
		err := preflight.Exec(CLI.Run.Cmd, CLI.Run.Hash)
		if err != nil {
			os.Exit(1)
		}

	case "check <hash|url>":
		// piping
		var fin io.Reader = os.Stdin
		s, err := ioutil.ReadAll(fin)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		content := string(s)
		res, err := preflight.Check(content, CLI.Check.Hash)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if !res.Ok {
			preflight.Porcelain.CheckFailed(res)
			os.Exit(1)
		}
		fmt.Print(content) // give back so piping can continue

	case "check <hash|url> <cmd>":
		s, err := ioutil.ReadFile(CLI.Check.Cmd[0])
		if err != nil {
			fmt.Printf("cannot open %v: %v", CLI.Check.Cmd[0], err)
			os.Exit(1)
		}

		res, err := preflight.Check(string(s), CLI.Check.Hash)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if !res.Ok {
			preflight.Porcelain.CheckFailed(res)
			os.Exit(1)
		}

	// XXX need some DRY
	case "create":
		s, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if CLI.Create.Digest == "" {
			CLI.Create.Digest = "sha256"
		}

		res, err := preflight.Check(string(s), fmt.Sprintf("%v=?", CLI.Create.Digest))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		if res.HasLookupVulns() {
			preflight.Porcelain.CheckFailed(res)
			os.Exit(1)
		}

		fmt.Printf("%v=%v\n", CLI.Create.Digest, res.ActualDigest.For(CLI.Create.Digest))

	case "create <file>":
		s, err := ioutil.ReadFile(CLI.Create.File)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if CLI.Create.Digest == "" {
			CLI.Create.Digest = "sha256"
		}

		res, err := preflight.Check(string(s), fmt.Sprintf("%v=?", CLI.Create.Digest))

		if res.HasLookupVulns() {
			preflight.Porcelain.CheckFailed(res)
			os.Exit(1)
		}

		fmt.Printf("%v=%v\n", CLI.Create.Digest, res.ActualDigest.For(CLI.Create.Digest))

	default:
		println(ctx.Command())
	}
}
