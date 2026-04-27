// Package main is the fakeaws entry point.
//
// fakeaws is a local Go-based mock of the AWS HTTP API surface. It boots
// a chi router holding one *Application struct, which holds one
// *Repository, which holds one SQLite handle. Adding a service is one
// Go file. See concepts.md and AGENTS.md for the full picture.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/redscaresu/fakeaws/handlers"
)

func main() {
	port := flag.Int("port", 8082, "HTTP listen port (default 8082; mockway uses 8080, fakegcp 8081)")
	dbPath := flag.String("db", ":memory:", "SQLite path; ':memory:' for ephemeral, file path for persistent")
	echo := flag.Bool("echo", false, "log every request method+path (useful for discovering unimplemented endpoints)")
	flag.Parse()

	app, err := handlers.NewApplication(*dbPath, *echo)
	if err != nil {
		log.Fatalf("fakeaws: init: %v", err)
	}
	defer app.Close()

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("fakeaws: listening on %s (db=%s, echo=%v)", addr, *dbPath, *echo)
	if err := http.ListenAndServe(addr, app.Router()); err != nil {
		log.Fatalf("fakeaws: serve: %v", err)
	}
}
