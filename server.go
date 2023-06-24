package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
	"github.com/tidwall/gjson"
)

type Config struct {
	ServerURL           string `json:"SERVER_URL"`
	CertFile            string `json:"CERT_FILE"`
	KeyFile             string `json:"KEY_FILE"`
	CaFile              string `json:"CA_FILE"`
	EsUrl               string `json:"ES_URL"`
	IndexName           string `json:"INDEX_NAME"`
	EsUsername          string `json:"ES_USERNAME"`
	EsPasswordEnv       string `json:"ES_PASSWORD_ENV"`
	EsIgnoreCertErrors  bool   `json:"ES_IGNORE_CERT_ERRORS"`
	LookbackTimeMinutes int    `json:"LOOKBACK_TIME_MINUTES"`
	LogSyslogServer     string `json:"LOG_SYSLOG_SERVER"`
}

func main() {
	file, _ := os.Open("config.json")
	defer file.Close()

	decoder := json.NewDecoder(file)
	conf := Config{}
	err := decoder.Decode(&conf)

	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(conf.CertFile, conf.KeyFile)
	if err != nil {
		log.Fatalf("unable to load server cert and key: %v", err)
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile(conf.CaFile)
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
		Addresses: []string{conf.EsUrl},
		Username:  conf.EsUsername,
		Password:  os.Getenv(conf.EsPasswordEnv), // retrieve password from environment variable
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: conf.EsIgnoreCertErrors,
			},
		},
	}
	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("error setting up Elasticsearch client: %s", err)
	}

	// Set up logrus logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})
	logFile, err := os.OpenFile("server.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	defer logFile.Close()

	// Set up syslog writer if needed
	if conf.LogSyslogServer != "" {
		hook, err := logrus_syslog.NewSyslogHook("udp", conf.LogSyslogServer, syslog.LOG_INFO, "")
		if err != nil {
			logger.Error("Unable to connect to local syslog daemon")
		} else {
			logrus.AddHook(hook)
		}
	}
	mw := io.MultiWriter(os.Stdout, logFile, logger.Writer())
	logrus.SetOutput(mw)

	// Set up HTTP server
	server := &http.Server{
		Addr:         conf.ServerURL,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 20 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if request is a GET request
			if r.Method != http.MethodGet {
				http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
				logrus.WithFields(logrus.Fields{
					"ip":     r.RemoteAddr,
					"method": r.Method,
				}).Warning("Client requested invalid method")
				return
			}

			// Check if path is valid
			if !strings.HasPrefix(r.URL.Path, "/interface_check/") {
				http.Error(w, "Invalid request path", http.StatusNotFound)
				logrus.WithFields(logrus.Fields{
					"ip":   r.RemoteAddr,
					"path": r.URL.Path,
				}).Warning("Client requested invalid path")
				return
			}

			// Extract interface from request path
			interfaceName := strings.TrimPrefix(r.URL.Path, "/interface_check/")
			// Sanitize the input to prevent path traversal attacks
			if strings.Contains(interfaceName, "/") {
				http.Error(w, "Invalid interface name", http.StatusBadRequest)
				logrus.WithFields(logrus.Fields{
					"ip":        r.RemoteAddr,
					"interface": interfaceName,
				}).Warning("Client requested invalid interface name")
				return
			}
			// TODO: Check if interface is available

			// Perform Elasticsearch query
			query := fmt.Sprintf(`
				{
					"query": {
						"bool": {
							"must": [
								{
									"match": {
										"suricata.eve.in_iface": "%s"
									}
								},
								{
									"range": {
										"@timestamp": {
											"gte": "now-%dm"
										}
									}
								}
							]
						}
					},
					"size": 1
				}
			`, interfaceName, conf.LookbackTimeMinutes)

			res, err := es.Search(
				es.Search.WithContext(context.Background()),
				es.Search.WithIndex(conf.IndexName),
				es.Search.WithBody(strings.NewReader(query)),
			)

			// Print the response body to stdout
			fmt.Println(res.String())

			if err != nil {
				http.Error(w, "Error performing search", http.StatusInternalServerError)
				logrus.WithFields(logrus.Fields{
					"ip":    r.RemoteAddr,
					"error": err,
				}).Error("Error performing Eleasticsearch search")
				return
			}

			if res.IsError() {
				// Log error message
				logrus.WithFields(logrus.Fields{
					"ip":              r.RemoteAddr,
					"response_status": res.Status(),
					"response_string": res.String(),
				}).Error("Error performing Eleasticsearch search")
				return
			}

			defer res.Body.Close()

			body, err := ioutil.ReadAll(res.Body)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"ip":    r.RemoteAddr,
					"error": err,
				}).Error("Error reading response body")
				http.Error(w, "Error reading response body from ES", http.StatusInternalServerError)
				return
			}

			var data map[string]interface{}
			err = json.Unmarshal(body, &data)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"ip":    r.RemoteAddr,
					"error": err,
				}).Error("Error unmarshalling response body")
				http.Error(w, "Error unmarshalling response body from ES", http.StatusInternalServerError)
				return
			}

			// Get the hits
			valid := gjson.Valid(string(body))
			if !valid {
				logrus.WithFields(logrus.Fields{
					"ip":    r.RemoteAddr,
					"error": err,
				}).Error("Error parsing response body")
				http.Error(w, "Error parsing response body from ES", http.StatusInternalServerError)
				return
			}

			hits := gjson.Get(string(body), "hits.total.value")
			if !hits.Exists() {
				logrus.WithFields(logrus.Fields{
					"ip":    r.RemoteAddr,
					"error": err,
				}).Error("Error parsing response body")
				http.Error(w, "Error parsing response body from ES", http.StatusInternalServerError)
				return
			}
			fmt.Println(hits)

			// Check if we have hits
			if hits.Int() > 0 {
				logrus.WithFields(logrus.Fields{
					"ip":        r.RemoteAddr,
					"interface": interfaceName,
				}).Info("Interface is up")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Interface is up"))
				return
			} else {
				logrus.WithFields(logrus.Fields{
					"ip":        r.RemoteAddr,
					"interface": interfaceName,
				}).Info("Interface is down")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Interface is down"))
				return
			}

		}),
	}

	// Start server
	log.Fatal(server.ListenAndServeTLS("", ""))
}
