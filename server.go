package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
)

var (
	certFile = "/path/to/server.crt"
	keyFile  = "/path/to/server.key"
	caFile   = "/path/to/ca.crt"
)

func main() {
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("unable to load server cert and key: %v", err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		log.Fatalf("unable to read CA cert: %v", err)
	}

	// Create CA cert pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}

	// Set up Elasticsearch client
	cfg := elasticsearch.Config{
		Addresses: []string{
			"http://localhost:9200", // replace with your Elasticsearch server address
		},
		Username: "user", // replace with your Elasticsearch username
		Password: "pass", // replace with your Elasticsearch password
	}
	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("error setting up Elasticsearch client: %s", err)
	}

	// Set up HTTP server
	server := &http.Server{
		Addr:         ":8080",
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract interface from request path
			interfaceName := strings.TrimPrefix(r.URL.Path, "/interface_check/")
			// Sanitize the input to prevent path traversal attacks
			if strings.Contains(interfaceName, "/") {
				http.Error(w, "Invalid interface name", http.StatusBadRequest)
				return
			}
			// TODO: Check if interface is available

			// Perform Elasticsearch query
			query := `
            {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "suricata.interface": "%s"
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": "now-90m"
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": 1
            }
        `

			res, err := es.Search(
				es.Search.WithContext(context.Background()),
				es.Search.WithIndex("pfelk-*"), // Replace with your desired index name
				es.Search.WithBody(strings.NewReader(query)),
			)

			// Print the response body to stdout
			fmt.Println(res.String())

			if err != nil {
				log.Printf("error performing search: %s", err)
				http.Error(w, "Error performing search", http.StatusInternalServerError)
				return
			}

			/* if res.IsError() {
				log.Printf("search request failed: %s", res.Status())
				http.Error(w, "Error performing search", http.StatusInternalServerError)
				return
			}

			// Check if we have hits
			if res.TotalHits() > 0 {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			} */
		}),
	}

	// Start server
	log.Fatal(server.ListenAndServeTLS("", ""))
}
