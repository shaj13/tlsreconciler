package tlsreconciler

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithDurationRelaod(t *testing.T) {
	opt := WithDurationRelaod(time.Millisecond * 100)
	r := newReconciler()
	opt.apply(r)

	for i := 0; i < 5; i++ {
		require.False(t, r.reload())
		time.Sleep(time.Millisecond * 100)
		require.True(t, r.reload())
	}
}

func TestWithSigHupReload(t *testing.T) {
	c := make(chan os.Signal, 2)
	c <- syscall.SIGHUP
	c <- syscall.SIGTERM

	opt := WithSIGHUPReload(c)
	r := newReconciler()
	opt.apply(r)

	require.True(t, r.reload())
	require.False(t, r.reload())
	require.False(t, r.reload())
}

func TestOptions(t *testing.T) {
	tests := []struct {
		opt    Option
		assert func(r *reconciler)
	}{
		{
			opt: WithVerifyConnection(),
			assert: func(r *reconciler) {
				require.NotNil(t, r.config.VerifyConnection)
				require.True(t, r.config.InsecureSkipVerify)
			},
		},
		{
			opt: WithProvider(testProvider{}),
			assert: func(r *reconciler) {
				require.Equal(t, testProvider{}, r.p)
				require.NotNil(t, r.config.GetCertificate)
				require.NotNil(t, r.config.GetClientCertificate)
			},
		},
		{
			opt: WithCertificatesPaths("", "", ""),
			assert: func(r *reconciler) {
				_, ok := r.p.(fileSystemProvider)
				require.True(t, ok)
				require.NotNil(t, r.config.GetCertificate)
				require.NotNil(t, r.config.GetClientCertificate)
			},
		},
		{
			opt: WithRootsLimit(5),
			assert: func(r *reconciler) {
				require.Equal(t, uint(5), r.rootsLimit)
			},
		},
		{
			opt: WithReloadFunc(func() bool {
				return true
			}),
			assert: func(r *reconciler) {
				require.True(t, r.reload())
			},
		},
		{
			opt: WithReloadFunc(func() bool {
				return true
			}),
			assert: func(r *reconciler) {
				require.True(t, r.reload())
			},
		},
		{
			opt: WithOnReload(func(c *tls.Config) {}),
			assert: func(r *reconciler) {
				require.NotNil(t, r.onReload)
			},
		},
	}

	for _, tt := range tests {
		r := newReconciler()
		tt.opt.apply(r)
		tt.assert(r)
	}
}

func TestTLSConfig(t *testing.T) {
	const serverName = "TestServerName"

	cfg := TLSConfig(optionFunc(func(r *reconciler) {
		r.config.ServerName = serverName
	}))
	require.Equal(t, serverName, cfg.ServerName)

	cfg = TLSConfig()
	require.Empty(t, cfg.ServerName)
}

func TestReconcilerCertificates(t *testing.T) {
	tests := []struct {
		p        testProvider
		subjects [][]byte
		i        int
	}{
		{
			p: testProvider{
				err: fmt.Errorf(""),
			},
			i: 1,
		},
		{
			p: testProvider{
				cert: new(tls.Certificate),
			},
			i: 1,
		},
		{
			p: testProvider{
				cert: new(tls.Certificate),
				ca:   &x509.Certificate{RawSubject: []byte("test")},
			},
			subjects: [][]byte{[]byte("test")},
			i:        2,
		},
	}

	for _, tt := range tests {
		r := newReconciler()
		r.p = tt.p

		for i := 0; i < tt.i-1; i++ {
			_, _, _ = r.certificates()
		}

		cert, pool, err := r.certificates()

		if tt.p.err != nil {
			require.Equal(t, tt.p.err, err)
			continue
		}

		require.NoError(t, err)
		require.Equal(t, tt.p.cert, cert)

		if len(tt.subjects) > 0 {
			require.Equal(t, tt.subjects, pool.Subjects())
		} else {
			require.Nil(t, pool)
		}
	}
}

func TestReconcilerNeedReload(t *testing.T) {
	relaod := false
	r := new(reconciler)
	r.reload = func() bool { return relaod }

	require.True(t, r.needReload())
	require.False(t, r.needReload())
	relaod = true
	require.True(t, r.needReload())
}

func TestReconcilerVerifyConnection(t *testing.T) {
	p := fileSystemProvider{"./testdata/cert", "./testdata/cert", "./testdata/key"}
	_, certs, err := p.Certificates()
	require.NoError(t, err)

	tests := []struct {
		p        Provider
		cs       tls.ConnectionState
		auth     tls.ClientAuthType
		time     func() time.Time
		contains string
	}{
		{
			p:        fileSystemProvider{},
			contains: "certificates path missing",
		},
		{
			p:    p,
			auth: tls.NoClientCert,
		},
		{
			p: p,
			cs: tls.ConnectionState{
				PeerCertificates: certs,
			},
			time: func() time.Time {
				return time.Date(2017, 11, 20, 0, 0, 0, 0, time.UTC)
			},
			auth:     tls.RequireAndVerifyClientCert,
			contains: "incompatible key usage",
		},
		{
			p: p,
			cs: tls.ConnectionState{
				PeerCertificates: certs,
			},
			time: func() time.Time {
				return time.Date(2017, 11, 20, 0, 0, 0, 0, time.UTC)
			},
		},
	}

	for _, tt := range tests {
		r := newReconciler()
		r.p = tt.p
		r.config.Time = tt.time
		r.config.ClientAuth = tt.auth

		err := r.verifyConnection(tt.cs)

		if len(tt.contains) > 0 {
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.contains)
			continue
		}

		require.NoError(t, err)
	}
}
func TestFileSystemProvider(t *testing.T) {
	tests := []struct {
		p        fileSystemProvider
		contains string
		noCA     bool
	}{
		{
			p:        fileSystemProvider{},
			contains: "certificates path missing",
		},
		{
			p:        fileSystemProvider{"", "", ""},
			contains: "no such file or directory",
		},
		{
			p:    fileSystemProvider{"", "./testdata/cert", "./testdata/key"},
			noCA: true,
		},
		{
			p:        fileSystemProvider{"/not/found", "./testdata/cert", "./testdata/key"},
			contains: "no such file or directory",
		},
		{
			p: fileSystemProvider{"./testdata/cert", "./testdata/cert", "./testdata/key"},
		},
	}

	for _, tt := range tests {
		cert, ca, err := tt.p.Certificates()
		if len(tt.contains) > 0 {
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.contains)
			continue
		}

		require.NoError(t, err)
		require.NotNil(t, cert)
		require.Equal(t, tt.noCA, ca == nil)
	}
}

func TestReconciliation(t *testing.T) {
	r := newReconciler()
	p := new(testProvider)
	r.rootsLimit = 1
	r.reload = func() bool { return true }
	r.p = p

	for i := 0; i < 10; i++ {
		raw := [][]byte{[]byte(strconv.Itoa(i))}
		cert := &tls.Certificate{Certificate: raw}
		ca := x509.Certificate{RawSubject: raw[0]}
		p.cert = cert
		p.ca = &ca

		rcert, pool, err := r.certificates()

		require.NoError(t, err)
		require.Equal(t, cert, rcert)
		require.Equal(t, raw, pool.Subjects())
		require.Equal(t, r.rootsLimit, uint(r.ll.Len()))
	}
}

func BenchmarkReconcilerCertificates(b *testing.B) {
	t := time.NewTimer(time.Millisecond)
	defer t.Stop()

	r := newReconciler()
	r.reload = func() bool {
		select {
		case <-t.C:
			return true
		default:
			return false
		}
	}

	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			_, _, err := r.certificates()
			require.NoError(b, err)
		}
	})
}

type testProvider struct {
	err  error
	ca   *x509.Certificate
	cert *tls.Certificate
}

func (p testProvider) Certificates() (*tls.Certificate, []*x509.Certificate, error) {
	roots := []*x509.Certificate{}
	if p.ca != nil {
		roots = append(roots, p.ca)
	}
	return p.cert, roots, p.err
}
