package webapi

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const responseWriteTimeout = 60 * time.Second

// ServeHTTPS refreshes the active certificate without interrupting requests.
// A mismatched pair during a renewal must not replace the last valid one.
func ServeHTTPS(ctx context.Context, address, certPath, keyPath string, handler http.Handler) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return err
	}

	return serveHTTPS(ctx, listener, certPath, keyPath, handler)
}

func serveHTTPS(ctx context.Context, listener net.Listener, certPath, keyPath string, handler http.Handler) error {
	bounded := &boundedListener{Listener: listener, slots: make(chan struct{}, 128), done: make(chan struct{})}
	defer bounded.Close()

	initial, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}

	var certMu sync.Mutex
	active := &initial
	nextCheck := time.Now().Add(time.Second)
	server := &http.Server{
		Handler:           handler,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      responseWriteTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				certMu.Lock()
				defer certMu.Unlock()
				if now := time.Now(); !now.Before(nextCheck) {
					nextCheck = now.Add(time.Second)
					if renewed, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
						active = &renewed
					}
				}
				return active, nil
			},
		},
		Protocols: new(http.Protocols),
	}
	// Match the original HTTP/1.1 listener and bound concurrent handshakes.
	server.Protocols.SetHTTP1(true)

	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(bounded, "", "") }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return errors.Join(err, server.Close())
		}
		return nil
	}
}

type boundedListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func (listener *boundedListener) Accept() (net.Conn, error) {
	select {
	case <-listener.done:
		return nil, net.ErrClosed
	case listener.slots <- struct{}{}:
	}
	conn, err := listener.Listener.Accept()
	if err != nil {
		<-listener.slots
		return nil, err
	}
	return &boundedConn{Conn: conn, release: func() { <-listener.slots }}, nil
}

func (listener *boundedListener) Close() error {
	listener.once.Do(func() { close(listener.done) })
	return listener.Listener.Close()
}

type boundedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (conn *boundedConn) Close() error {
	err := conn.Conn.Close()
	conn.once.Do(conn.release)
	return err
}
