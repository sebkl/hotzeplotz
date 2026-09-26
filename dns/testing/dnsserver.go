package main

import (
	"log"
	"os"

	"github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"github.com/sebkl/hotzeplotz/dns"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting local server on http://localhost:%s ...", port)
	// TODO: Why do we need this here if this is done by dns init function?
	funcframework.RegisterHTTPFunction("/", dns.UpdateHTTP)
	if err := funcframework.Start(port); err != nil {
		log.Fatalf("Starting local server failed: %v", err)
	}
}
