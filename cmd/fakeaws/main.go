// Package main is the fakeaws entry point.
//
// fakeaws is a local Go-based mock of the AWS HTTP API surface. It boots
// a chi router holding one *Application struct, which holds one
// *Repository, which holds one SQLite handle. Adding a service is one
// Go file. See concepts.md and AGENTS.md for the full picture.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
)

// adminTokenEnv supplies the admin token when -admin-token is not
// given; a flag value shows in ps, an environment variable does not.
const adminTokenEnv = "FAKEAWS_ADMIN_TOKEN"

func main() {
	opts, err := optionsFromFlags(os.Args[1:], os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		os.Exit(2) // flag has already printed the error and usage
	}

	app, err := handlers.NewApplication(opts)
	if err != nil {
		log.Fatalf("fakeaws: init: %v", err)
	}
	defer app.Close()

	log.Print(startupMessage(opts))
	if err := http.ListenAndServe(opts.ListenAddr(), app.Router()); err != nil {
		log.Fatalf("fakeaws: serve: %v", err)
	}
}

// optionsFromFlags parses args into Options. -admin-token beats the
// FAKEAWS_ADMIN_TOKEN environment variable, read through getenv.
// -account must be 12 digits, -region look like us-east-1, and -region
// comes only with -account.
func optionsFromFlags(args []string, getenv func(string) string) (handlers.Options, error) {
	var opts handlers.Options
	fs := flag.NewFlagSet("fakeaws", flag.ContinueOnError)
	fs.IntVar(&opts.Port, "port", 8082, "HTTP listen port (default 8082; mockway uses 8080, fakegcp 8081)")
	fs.StringVar(&opts.Bind, "bind", "", "listen host, e.g. 127.0.0.1; empty listens on all interfaces")
	fs.StringVar(&opts.DBPath, "db", ":memory:", "SQLite path; ':memory:' for ephemeral, file path for persistent")
	fs.BoolVar(&opts.Echo, "echo", false, "log every request method+path (useful for discovering unimplemented endpoints)")
	fs.StringVar(&opts.AdminToken, "admin-token", "", "require Authorization: Bearer <token> on /mock/*; else "+adminTokenEnv)
	fs.Func("account", "12-digit account id to store and answer as (default "+awsproto.FakeAccountID+"); refused when the db holds rows under another", func(v string) error {
		opts.AccountID = v
		return handlers.CheckAccountID(v)
	})
	fs.Func("region", "region to store with -account, e.g. us-east-1", func(v string) error {
		opts.Region = v
		return handlers.CheckRegion(v)
	})
	if err := fs.Parse(args); err != nil {
		return handlers.Options{}, err
	}
	if opts.Region != "" && opts.AccountID == "" {
		err := errors.New("-region needs -account")
		fmt.Fprintln(fs.Output(), err)
		fs.Usage()
		return handlers.Options{}, err
	}
	if opts.AdminToken == "" {
		opts.AdminToken = getenv(adminTokenEnv)
	}
	return opts, nil
}

// startupMessage says whether an admin token is set and never prints it.
func startupMessage(opts handlers.Options) string {
	return fmt.Sprintf("fakeaws: listening on %s (db=%s, echo=%v, admin-token set=%v)",
		opts.ListenAddr(), opts.DBPath, opts.Echo, opts.AdminToken != "")
}
