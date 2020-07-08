// Includes some code from src/crypto/tls/generate_cert.go

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {

	// Parse command line arguments
	var client bool
	var server bool
	var algo string
	var domain string
	var cn string
	var years int
	var months int
	var days int
	var hours int

	flag.BoolVar(&client, "client", false, "generate a client certificate.")
	flag.BoolVar(&server, "server", false, "generate a server certificate.")
	flag.StringVar(&algo, "algo", "ecdsa", "crypto algorithm - ecdsa or ed25519.")
	flag.StringVar(&domain, "domain", "example.com", "server domain.")
	flag.StringVar(&cn, "cn", "cn", "client certificate CN.")
	flag.IntVar(&years, "years", 0, "years of validity.")
	flag.IntVar(&months, "months", 0, "months of validity.")
	flag.IntVar(&days, "days", 0, "days of validity.")
	flag.IntVar(&hours, "hours", 0, "hours of validity.")
	flag.Parse()

	// Check validity of supplied arguments
	if client && server {
		log.Fatal("You can only specify one of -server or -client!")
	} else if !client && !server {
		log.Fatal("You must specify -server or -client!")
	}

	// Build certificate template
	var template x509.Certificate
	if server {
		template = getServerCertTemplate(domain, years, months, days, hours)
	} else {
		template = getClientCertTemplate(cn, years, months, days, hours)
	}

	// Generate keys, sign cert and write everything to disk
	if algo == "ecdsa" {
		writeEcdsaKeyAndCertFromTemplate(template)
	} else if algo == "ed25519" {
		writeEd25519KeyAndCertFromTemplate(template)
	}
}

func getServerCertTemplate(domain string, years int, months int, days int, hours int) x509.Certificate {
	return getCommonCertTemplate()
}

func getClientCertTemplate(commonName string, years int, months int, days int, hours int) x509.Certificate {
	return getCommonCertTemplate()
}

func getCommonCertTemplate() x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now(),
	}
	return template
}

func writeEcdsaKeyAndCertFromTemplate(template x509.Certificate) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}
	writeToPem(priv, cert)
}

func writeEd25519KeyAndCertFromTemplate(template x509.Certificate) {
	var pub ed25519.PublicKey
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.CreateCertificate(nil, &template, &template, pub, priv)
	if err != nil {
		log.Fatal(err)
	}
	writeToPem(priv, cert)
}

func writeToPem(privkey interface{}, cert []byte) {
	// Write cert
	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}
	log.Print("wrote cert.pem\n")

	// Write key
	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privkey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}
	log.Print("wrote key.pem\n")
}
