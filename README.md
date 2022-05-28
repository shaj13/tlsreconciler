[![PkgGoDev](https://pkg.go.dev/badge/github.com/shaj13/tlsreconciler)](https://pkg.go.dev/github.com/shaj13/tlsreconciler)
[![Go Report Card](https://goreportcard.com/badge/github.com/shaj13/tlsreconciler)](https://goreportcard.com/report/github.com/shaj13/tlsreconciler)
[![Coverage Status](https://coveralls.io/repos/github/shaj13/tlsreconciler/badge.svg?branch=main)](https://coveralls.io/github/shaj13/tlsreconciler?branch=main)
[![CircleCI](https://circleci.com/gh/shaj13/tlsreconciler/tree/main.svg?style=svg)](https://circleci.com/gh/shaj13/tlsreconciler/tree/main)

# TLS Reconciler
A Hitless TLS Certificate Rotation Reconciliation Library. 

## Introduction 
> If a certificate got issued, it will have to be rotated.
Rotating TLS certificates manually may quickly get out of hand—particularly when you have to manage hundreds of certificates—and becomes completely unmanageable if you issue certificates that expire within hours, instead of months.
tlsreconciler is here to help with that, by reloading rotated certificate including root CA and provide TLS reconciliation to connections in real time and without restarting the application. 

## Quickstart 
### Installing 
Using tlsreconciler is easy. First, use go get to install the latest version of the library.

```sh
go get github.com/shaj13/tlsreconciler
```
Next, include tlsreconciler in your application:
```go
import (
    "github.com/shaj13/tlsreconciler"
)
```

### Example
```go
package main

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

func main() {
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
```

# Contributing
1. Fork it
2. Download your fork to your PC (`git clone https://github.com/your_username/tlsreconciler && cd tlsreconciler`)
3. Create your feature branch (`git checkout -b my-new-feature`)
4. Make changes and add them (`git add .`)
5. Commit your changes (`git commit -m 'Add some feature'`)
6. Push to the branch (`git push origin my-new-feature`)
7. Create new pull request

# License
Libcache is released under the MIT license. See [LICENSE](https://github.com/shaj13/tlsreconciler/blob/main/LICENSE)