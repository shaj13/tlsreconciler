// Package tlsreconciler implements hitless TLS certificate rotation reconciliation,
// by using certificate selection during the TLS handshake that tls.Config exposes.
package tlsreconciler

import (
	"container/list"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/singleflight"
)

// Provider provides tls certificates. Any type that implements
// it may be used to reload and provide rotated certificates.
type Provider interface {
	// Certificates retruns last rotated client or server (leaf) certificate
	// alongside root CA, or an error if occurs.
	//
	// Certificate may return nil for root CAs, if a predefined ca pool sat in tls.Config.
	Certificates() (*tls.Certificate, []*x509.Certificate, error)
}

// Option configures reconciler using the functional options paradigm
// popularized by Rob Pike and Dave Cheney. If you're unfamiliar with this style,
// see https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html and
// https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis.
type Option interface {
	apply(*reconciler)
}

// OptionFunc implements Option interface.
type optionFunc func(*reconciler)

// apply the configuration to the provided config.
func (fn optionFunc) apply(r *reconciler) {
	fn(r)
}

// WithVerifyConnection set tls.Config.VerifyConnection to verify
// tls conn certificate, using the reconciler CA pool that
// fulfilled from the provider based on previous rotations,
// Otherwise, the system roots or the platform verifier are used.
//
// WithVerifyConnection also set tls.Config.InsecureSkipVerify
// to skip the default golang validation that tlsreconciler
// replacing. This will not disable VerifyConnection.
//
// See the documentation of WithRootsLimit.
//
// Note: tls.Config RootCAs and ClientCAs ignored
// when this option take place.
func WithVerifyConnection() Option {
	return optionFunc(func(r *reconciler) {
		r.config.VerifyConnection = r.verifyConnection
		r.config.InsecureSkipVerify = true
	})
}

// WithProvider sets tlsreconciler provider to retrieve
// latest certificates when there a reload signal.
func WithProvider(p Provider) Option {
	return optionFunc(func(r *reconciler) {
		r.p = p
		r.config.GetCertificate = r.getCertificate
		r.config.GetClientCertificate = r.getClientCertificate
	})
}

// WithCertificatesPaths sets tlsreconciler provider to retrieve
// latest certificates from the given paths when there a reload signal.
//
// Note: ca can be empty if reload CA not needed, or it can be path to CA bundle.
func WithCertificatesPaths(cert, key, ca string) Option {
	return WithProvider(fileSystemProvider{ca, cert, key})
}

// WithRootsLimit limits the number of old root CA to keep in the pool.
// One use case for this feature would be in a situation to keep backward
// compatibility to verify leaf certs of services that haven't reconciled
// there certificates yet.
//
// WithRootsLimit used WithVerifyConnection, Otherwise, It's noop
//
// Default 2.
func WithRootsLimit(n uint) Option {
	return optionFunc(func(r *reconciler) {
		r.rootsLimit = n
	})
}

// WithReloadFunc registers func to determine if
// need to reload certificate and call the provider
// to retrieve the latest certificates.
//
// Note: multiple goroutines may call f simultaneously.
func WithReloadFunc(f func() bool) Option {
	return optionFunc(func(r *reconciler) {
		r.reload = f
	})
}

// WithSIGHUPReload reload certificate and call the provider
// to retrieve the latest certificates when SIGHUP received.
func WithSIGHUPReload(c chan os.Signal) Option {
	return optionFunc(func(r *reconciler) {
		r.reload = func() bool {
			select {
			case sig := <-c:
				if sig == syscall.SIGHUP {
					return true
				}
				return false
			default:
				return false
			}
		}
	})
}

// WithDurationRelaod reload certificate and call the provider
// to retrieve the latest certificates when each duration elapse.
func WithDurationRelaod(dur time.Duration) Option {
	return optionFunc(func(r *reconciler) {
		mu := new(sync.Mutex)
		t := time.Now().Add(dur)

		r.reload = func() bool {
			mu.Lock()
			defer mu.Unlock()

			if time.Now().After(t) {
				t = time.Now().Add(dur)
				return true
			}

			return false
		}
	})
}

// WithOnReload registers a function to call on relaod.
// this can be used to rotate session tickets, or any
// additional purposes like loging.
//
// Reconciler calls f in its own goroutine.
func WithOnReload(f func(*tls.Config)) Option {
	return optionFunc(func(r *reconciler) {
		r.onReload = f
	})
}

// TLSConfig returns new tls.Config that reconcile certificates after a rotation.
// Calling TLSConfig without any option is similar to
//
//   new(tls.Config)
//
// See the documentation of options for more information.
func TLSConfig(opts ...Option) *tls.Config {
	if len(opts) == 0 {
		return new(tls.Config)
	}

	r := newReconciler()

	for _, opt := range opts {
		opt.apply(r)
	}

	return r.config
}

func newReconciler() *reconciler {
	return &reconciler{
		rootsLimit: 2,
		flight:     &singleflight.Group{},
		cond:       sync.NewCond(noopLocker{}),
		p:          noopProvider{},
		ll:         list.New(),
		config:     new(tls.Config),
		reload:     func() (ok bool) { return },
	}
}

type reconciler struct {
	// reloading indicates whether the certificate reload in is progress.
	// It is first in the struct because it is used in the hot path.
	// The hot path is inlined at every call site.
	// Placing reloading first allows more compact instructions on some architectures (amd64/386),
	// and fewer instructions (to calculate offset) on other architectures.
	reloading uint32
	// limit the number of rotated root certificates.
	rootsLimit uint
	// flight ensures that each reload is only fetched once
	// regardless of the number of concurrent callers.
	flight *singleflight.Group
	// trigger reload at least one time on first use.
	once sync.Once
	// cond to waiting for or announcing the occurrence of an relaod to finish.
	cond *sync.Cond
	// pool hold *x509.CertPool accessible by goroutines simultaneously.
	pool atomic.Value
	// cert hold *tls.Certificate accessible by goroutines simultaneously.
	cert atomic.Value
	// p represent the certs provider.
	p Provider
	// ll hold new and old root certs guarded by rootsLimit.
	ll *list.List
	// config that the reconciler works on.
	config *tls.Config
	// reload indicates if need reload.
	reload func() bool
	// invoked on reload evnet.
	onReload func(*tls.Config)
}

// getCertificate returns the last reloaded certificate.
// getCertificate implements tls.Config.GetCertificate.
func (r *reconciler) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, _, err := r.certificates()
	return cert, err
}

// getClientCertificate returns the last reloaded certificate.
// getClientCertificate implements tls.Config.GetClientCertificate.
func (r *reconciler) getClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert, _, err := r.certificates()
	return cert, err
}

// verifyConnection verify tls conn certificate using the last reloaded roots.
// verifyConnection implements tls.Config.VerifyConnection.
func (r *reconciler) verifyConnection(cs tls.ConnectionState) error {
	_, pool, err := r.certificates()
	if err != nil {
		return err
	}

	if r.config.ClientAuth < tls.VerifyClientCertIfGiven &&
		len(cs.PeerCertificates) == 0 {
		return nil
	}

	opts := x509.VerifyOptions{
		Roots:         pool,
		DNSName:       r.config.ServerName,
		Intermediates: x509.NewCertPool(),
	}

	if r.config.Time != nil {
		opts.CurrentTime = r.config.Time()
	}

	if r.config.ClientAuth >= tls.VerifyClientCertIfGiven {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// Copy intermediates certificates to verify options from cs if needed.
	// ignore cs.PeerCertificates[0] it refer to client certificates.
	for _, inter := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(inter)
	}

	_, err = cs.PeerCertificates[0].Verify(opts)
	return err
}

func (r *reconciler) certificates() (cert *tls.Certificate, pool *x509.CertPool, err error) {
	// Wait for new certificates.
	for atomic.LoadUint32(&r.reloading) == 1 {
		r.cond.Wait()
	}

	if r.needReload() {
		// Prevent returning old certificates.
		atomic.StoreUint32(&r.reloading, 1)

		// Ensures that each reload is only fetched once.
		// the reloading mechanism can only dedup calls that
		// overlap concurrently, therefore, there a chance
		// of goroutines bypass atomic reloading and enter
		// reload, if there more than one signal.
		_, err, _ = r.flight.Do("reconciler", func() (interface{}, error) {
			cert, roots, err := r.p.Certificates()
			if err != nil {
				return nil, err
			}

			if len(roots) > 0 {

				pool := x509.NewCertPool()

				for _, ca := range roots {
					r.ll.PushFront(ca)
					// Remove last root ca, reached the limit.
					if uint(r.ll.Len()) > r.rootsLimit {
						e := r.ll.Back()
						r.ll.Remove(e)
					}
				}

				for e := r.ll.Front(); e != nil; e = e.Next() {
					pool.AddCert(e.Value.(*x509.Certificate))
				}

				r.pool.Store(pool)
			}

			r.cert.Store(cert)

			if r.onReload != nil {
				go r.onReload(r.config)
			}

			// Release goroutines to read latest certs.
			atomic.StoreUint32(&r.reloading, 0)
			r.cond.Broadcast()
			return nil, nil
		})
	}

	if v, ok := r.cert.Load().(*tls.Certificate); ok {
		cert = v
	}

	if v, ok := r.pool.Load().(*x509.CertPool); ok {
		pool = v
	}

	return cert, pool, err
}

func (r *reconciler) needReload() (ok bool) {
	r.once.Do(func() {
		ok = true
	})

	return ok || r.reload()
}

type fileSystemProvider []string

func (fsp fileSystemProvider) Certificates() (*tls.Certificate, []*x509.Certificate, error) {
	if len(fsp) != 3 {
		return nil, nil, errors.New("tlsreconciler: certificates path missing")
	}

	caFile, certFile, keyFile := fsp[0], fsp[1], fsp[2]

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}

	if len(caFile) == 0 {
		return &cert, nil, nil
	}

	caPEMBlock, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, err
	}

	var (
		p     *pem.Block
		roots []*x509.Certificate
	)

	for {

		p, caPEMBlock = pem.Decode(caPEMBlock)
		if p == nil {
			break
		}

		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, nil, err
		}

		roots = append(roots, cert)

	}

	return &cert, roots, err
}

type noopLocker struct{}

func (noopLocker) Lock()   {}
func (noopLocker) Unlock() {}

type noopProvider struct{}

func (noopProvider) Certificates() (*tls.Certificate, []*x509.Certificate, error) {
	return nil, nil, nil
}
