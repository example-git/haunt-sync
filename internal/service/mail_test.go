package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSMTPTransport(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	for _, tc := range []struct {
		name                       string
		startTLS, trusted, success bool
	}{{"verified encrypted delivery", true, true, true}, {"untrusted certificate rejected", true, false, false}, {"plaintext relay rejected", false, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			delivered := make(chan string, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				stream := textproto.NewConn(conn)
				stream.PrintfLine("220 localhost test fixture")
				for {
					line, err := stream.ReadLine()
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if tc.startTLS {
							stream.PrintfLine("250-localhost")
							stream.PrintfLine("250 STARTTLS")
						} else {
							stream.PrintfLine("250 localhost")
						}
					case line == "STARTTLS":
						stream.PrintfLine("220 begin TLS")
						secured := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
						if err = secured.Handshake(); err != nil {
							return
						}
						stream = textproto.NewConn(secured)
					case strings.HasPrefix(line, "MAIL FROM:") || strings.HasPrefix(line, "RCPT TO:"):
						stream.PrintfLine("250 accepted")
					case line == "DATA":
						stream.PrintfLine("354 send body")
						body, err := stream.ReadDotBytes()
						if err != nil {
							return
						}
						delivered <- string(body)
						stream.PrintfLine("250 queued")
					case line == "QUIT":
						stream.PrintfLine("221 done")
						return
					default:
						stream.PrintfLine("500 unsupported")
					}
				}
			}()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			cfg := Config{SMTPHost: "localhost", SMTPPort: port, MailFrom: "sync@example.test"}
			if tc.trusted {
				cfg.SMTPCAFile = ca
			}
			err = (&SMTPMailer{Config: cfg}).Send(t.Context(), "recipient@example.test", "https://trusted.example.test/#synthetic-verification")
			if tc.success {
				if err != nil {
					t.Fatal(err)
				}
				body := <-delivered
				if !strings.Contains(body, "synthetic-verification") || !strings.Contains(body, "does not unlock your encrypted backup") {
					t.Fatal("verification message missing")
				}
			} else {
				if err == nil {
					t.Fatal("unsafe SMTP transport was accepted")
				}
				select {
				case <-delivered:
					t.Fatal("mail delivered over an unsafe transport")
				default:
				}
			}
			<-finished
		})
	}
}
