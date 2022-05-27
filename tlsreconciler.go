package tlsreconciler

import (
	"container/list"
	"crypto/tls"
	"crypto/x509"
	"sync/atomic"
)

type Provider interface {
	Certificate() (*tls.Certificate, error)
	Root() (*x509.Certificate, error)
}

type reconciler struct {
	p        Provider
	ll       *list.List
	certc    chan struct{}
	rootc    chan struct{}
	sema     chan struct{}
	pool     atomic.Value
	maxRoots uint
	config   *tls.Config
}

func (r *reconciler) verifyConnection(cs tls.ConnectionState) error {
	select {
	case <-r.rootc:
		cert, err := r.p.Root()
		if err != nil {
			return err
		}

		if cert == nil {
			break
		}

		//
		r.sema <- struct{}{}
		r.ll.PushFront(cert)

		if uint(r.ll.Len()) > r.maxRoots {
			e := r.ll.Back()
			r.ll.Remove(e)
		}

		pool := x509.NewCertPool()
		for e := r.ll.Front(); e != nil; e = e.Next() {
			pool.AddCert(e.Value.(*x509.Certificate))
		}

		r.pool.Store(pool)
		<-r.sema
	default:
	}

	if r.config.ClientAuth < tls.VerifyClientCertIfGiven &&
		len(cs.PeerCertificates) == 0 {
		return nil
	}

	opts := x509.VerifyOptions{
		DNSName:       r.config.ServerName,
		Intermediates: x509.NewCertPool(),
	}

	if v := r.pool.Load(); v != nil {
		opts.Roots = v.(*x509.CertPool)
	}

	if r.config.Time != nil {
		opts.CurrentTime = r.config.Time()
	}

	if r.config.ClientAuth >= tls.VerifyClientCertIfGiven {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// copy intermediates certificates to verify options from cs if needed.
	// ignore cs.PeerCertificates[0] it refer to client certificates.
	for _, inter := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(inter)
	}

	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}
