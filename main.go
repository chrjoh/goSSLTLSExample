package main

import (
	"net/http"
	"html/template"
	"github.com/bmizerany/pat"

	"fmt"
	"crypto/tls"
)

type Answer struct {
	Host                           string
	Versions                       []string
	VersionsNotSupported           []string
	CipherSuites                   []string
	CipherSuitesNotSupported       []string
	NegotiatedProtocol             string
}

var tlsCipherLookup = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                `TLS_RSA_WITH_RC4_128_SHA`,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           `TLS_RSA_WITH_3DES_EDE_CBC_SHA`,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            `TLS_RSA_WITH_AES_128_CBC_SHA`,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            `TLS_RSA_WITH_AES_256_CBC_SHA`,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        `TLS_ECDHE_ECDSA_WITH_RC4_128_SHA`,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          `TLS_ECDHE_RSA_WITH_RC4_128_SHA`,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     `TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA`,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`,
}

var tlsVersionLookup = map[uint16]string{
	tls.VersionSSL30: `VersionSSL30`,
	tls.VersionTLS10: `VersionTLS10`,
	tls.VersionTLS11: `VersionTLS11`,
	tls.VersionTLS12: `VersionTLS12`,
}

func main() {
	ListenAndServe(":8080")
}

func handler(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("templates/query.html")
	t.Execute(w, nil)
}

func queryHandler(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	supportedCiphers, notSupportedCiphers := tlsCiphersSupported(host)
	supportedversions, notSupportedVersions := tlsVersionsSupported(host)
	a := &Answer{
		Host: host,
		Versions: supportedversions,
		VersionsNotSupported: notSupportedVersions,
		CipherSuites: supportedCiphers,
		CipherSuitesNotSupported: notSupportedCiphers,
	}
	t, _ := template.ParseFiles("templates/answer.html")
	t.Execute(w, a)
}

func ListenAndServe(addr string) error {
	mux := pat.New()
	mux.Post("/", http.HandlerFunc(queryHandler))
	mux.Get("/", http.HandlerFunc(handler))
	http.Handle("/", mux)
	return http.ListenAndServe(addr, nil)
}

func tlsCiphersSupported(url string) ([]string, []string) {
	ciphers := knownCiphers()
	supportedCiphers := []string{}
	notSupportedCiphers := []string{}
	for i := 0; i < len(ciphers); i++ {
		config := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites: []uint16{ciphers[i]},
			MinVersion: tls.VersionSSL30,
		}
		err := tlsState(url, config)
		if err == nil {
			supportedCiphers = append(supportedCiphers, tlsCipherLookup[ciphers[i]])
		} else {
			notSupportedCiphers = append(notSupportedCiphers, tlsCipherLookup[ciphers[i]])
		}
	}
	return supportedCiphers, notSupportedCiphers
}


func tlsVersionsSupported(host string) ([]string, []string) {
	ciphers := knownCiphers()
	versions := knownVersions()
	supportedVersions := []string{}
	notSupportedVersions := []string{}
	for i := 0; i < len(versions); i++ {
		config := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites: ciphers,
			MaxVersion: versions[i],
		}
		err := tlsState(host, config)
		if err == nil {
			supportedVersions = append(supportedVersions, tlsVersionLookup[versions[i]])
		} else {
			notSupportedVersions = append(notSupportedVersions, tlsVersionLookup[versions[i]])
		}
	}
	return supportedVersions, notSupportedVersions
}

func knownCiphers() []uint16 {
	return []uint16{0x0005, 0x000a, 0x002f, 0x0035, 0xc007, 0xc009, 0xc00a,
		0xc011, 0xc012, 0xc013, 0xc014, 0xc02f, 0xc02b}
}

func knownVersions() []uint16 {
	return []uint16{tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11,
		tls.VersionTLS12}
}

func tlsState(host string, config *tls.Config) error {
	conn, err := tls.Dial("tcp", host+":443", config)
	if err != nil {
		return err
	}
	err = conn.Handshake()
	if err != nil {
		fmt.Printf("Failed handshake:%v\n", err)
		return err
	}
	conn.Close()
	return nil
}
