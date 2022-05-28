package tlsreconciler_test

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/shaj13/tlsreconciler"
)

func HelloWorld(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Hello World.\n"))
}

func Example() {
	sigc := make(chan os.Signal, 1)
	defer close(sigc)

	signal.Notify(sigc, syscall.SIGHUP)

	// Options
	sig := tlsreconciler.WithSIGHUPReload(sigc)
	certs := tlsreconciler.WithCertificatesPaths("cert_file", "cert_key", "cert_ca")
	verify := tlsreconciler.WithVerifyConnection()
	cb := tlsreconciler.WithOnReload(func(c *tls.Config) {
		log.Println("TLS certificates rotated !!")
	})

	config := tlsreconciler.TLSConfig(sig, certs, verify, cb)
	server := http.Server{
		Addr:      ":443",
		Handler:   http.HandlerFunc(HelloWorld),
		TLSConfig: config,
	}

	server.ListenAndServeTLS("", "")
}
