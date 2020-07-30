// Includes some code from src/crypto/tls/generate_cert.go

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {

	// Parse command line arguments
	var client bool
	var server bool
	var ed25519 bool
	var domain string
	var cn string
	var years int
	var months int
	var days int
	var hours int

	flag.BoolVar(&client, "client", false, "generate a client certificate.")
	flag.BoolVar(&server, "server", false, "generate a server certificate.")
	flag.BoolVar(&ed25519, "ed25519", false, "use ed25519 instead of ECDSA.")
	flag.StringVar(&domain, "domain", "example.com", "server domain.")
	flag.StringVar(&cn, "cn", "gemini", "client certificate CN.")
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

	// Compute validity dates
	if years+months+days+hours == 0 {
		if server {
			// Default server cert lifespan
			years = 5
		} else {
			// Default server cert lifespan
			days = 1
		}
	}
	notBefore := time.Now()
	notAfter := notBefore.AddDate(years, months, days)
	hoursDuration, _ := time.ParseDuration(fmt.Sprintf("%dh", hours))
	notAfter = notAfter.Add(hoursDuration)

	// Build certificate template
	var template x509.Certificate
	if server {
		template = getServerCertTemplate(domain, notBefore, notAfter)
	} else {
		template = getClientCertTemplate(cn, notBefore, notAfter)
	}

	// Generate keys, sign cert and write everything to disk
	if ed25519 {
		generateEd25519KeyAndCertFromTemplate(template, server)
	} else {
		generateEcdsaKeyAndCertFromTemplate(template, server)
	}
}

func getServerCertTemplate(domain string, notBefore time.Time, notAfter time.Time) x509.Certificate {
	template := getCommonCertTemplate(notBefore, notAfter)
	template.Subject = pkix.Name{
		CommonName: domain,
	}
	wildcard := "*." + domain
	template.DNSNames = append(template.DNSNames, domain)
	template.DNSNames = append(template.DNSNames, wildcard)
	return template
}

func getClientCertTemplate(cn string, notBefore time.Time, notAfter time.Time) x509.Certificate {
	template := getCommonCertTemplate(notBefore, notAfter)
	template.Subject = pkix.Name{
		CommonName: cn,
	}
	return template
}

func getCommonCertTemplate(notBefore time.Time, notAfter time.Time) x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	return template
}

func generateEcdsaKeyAndCertFromTemplate(template x509.Certificate, isServer bool) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}
	writeAndPrint(priv, cert, isServer)
}

func generateEd25519KeyAndCertFromTemplate(template x509.Certificate, isServer bool) {
	var pub ed25519.PublicKey
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.CreateCertificate(nil, &template, &template, pub, priv)
	if err != nil {
		log.Fatal(err)
	}
	writeAndPrint(priv, cert, isServer)
}

func writeAndPrint(privkey interface{}, cert []byte, isServer bool) {
	isClient := !isServer

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

	// Print fingerprint of client certs
	if isClient {
		hash := sha256.Sum256(cert)
		fingerprint := hex.EncodeToString(hash[:])
		log.Printf("Certificate fingerprint (SHA256): " + fingerprint)
	}
}
