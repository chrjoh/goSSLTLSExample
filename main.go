package main

import (
	"net/http"
	"html/template"
	"github.com/bmizerany/pat"

	"fmt"
	"crypto/tls"
)

type TLSSSL struct {
	Host      string
	Version   string
	Supported bool
	Sciphers  []string
	Nciphers  []string
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
	versions := knownVersions()
	a := []TLSSSL{}
	for i := 0; i < len(versions); i++ {
		version := tlsVersionLookup[versions[i]]
		err := tlsVersionSupported(host, versions[i])
		if err == nil {
			sc, nc := tlsCiphersSupported(host, versions[i])
			data := TLSSSL{Host: host, Version: version, Supported: true, Sciphers: sc, Nciphers: nc}
			a = append(a, data)
		} else {
			data := TLSSSL{Host: host, Version: version, Supported: false}
			a = append(a, data)
		}
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

func printAnswer(a []TLSSSL) {
	for i := 0; i < len(a); i++ {
		fmt.Printf("Version: %v, supported: %v\n", a[i].Version, a[i].Supported)
		if a[i].Supported {
			fmt.Printf("Suported ciphers\n")
			for sc := 0; sc < len(a[i].Sciphers); sc++ {
				fmt.Printf("%v\n", a[i].Sciphers[sc])
			}
			fmt.Printf("NOT Suported ciphers\n")
			for nc := 0; nc < len(a[i].Nciphers); nc++ {
				fmt.Printf("%v\n", a[i].Nciphers[nc])
			}
		}
	}
}

func tlsCiphersSupported(url string, version uint16) ([]string, []string) {
	ciphers := knownCiphers()
	supportedCiphers := []string{}
	notSupportedCiphers := []string{}
	for i := 0; i < len(ciphers); i++ {
		config := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites: []uint16{ciphers[i]},
			MaxVersion: version,
			MinVersion: version,
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


func tlsVersionSupported(host string, version uint16) error {
	ciphers := knownCiphers()
	config := &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites: ciphers,
		MaxVersion: version,
	}
	err := tlsState(host, config)
	return err
}

func knownCiphers() []uint16 {
	return keysFromMap((map[uint16]string)(tlsCipherLookup))
}

func knownVersions() []uint16 {
	return keysFromMap((map[uint16]string)(tlsVersionLookup))
}

func keysFromMap(myMap map[uint16]string) []uint16 {
	keys := make([]uint16, 0, len(myMap))
	for k := range myMap {
		keys = append(keys, k)
	}
	return keys
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
