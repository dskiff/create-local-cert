package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const KEY_SIZE = 4096

const CA_KEY_FILE = "ca.key"
const CA_CERT_FILE = "ca.crt"
const SERVER_KEY_FILE = "server.key"
const SERVER_CERT_FILE = "server.crt"

const KEY_FILE_MODE = 0400
const CERT_FILE_MODE = 0444

// Injected at build time
var build_version = "dev"
var build_commit = "none"
var build_date = "na"

func main() {
	log.Printf("create-local-cert %v (%v) built on %v\n", build_version, build_commit, build_date)
	log.Println()

	var outPath string
	var isUsingNameConstraints bool

	flag.StringVar(&outPath, "out", "./certs", "Output path for certificates")
	flag.BoolVar(&isUsingNameConstraints, "name-constraints", true, "Use name constraints in the CA certificate")
	flag.Parse()

	sans := flag.Args()
	if len(sans) == 0 {
		log.Fatal("failed: at least one SAN must be provided")
	}

	outPath, err := filepath.Abs(outPath)
	if err != nil {
		log.Fatal("failed to resolve outpath: ", err)
	}

	log.Println("Params:")
	log.Println("  SANs:", sans)
	log.Println("  outPath:", outPath)
	log.Println("  isUsingNameConstraints:", isUsingNameConstraints)
	log.Println()

	// Create the output directory
	if err := os.MkdirAll(outPath, 0755); err != nil {
		log.Fatal("failed to create output directory: ", err)
	}

	log.Println("Creating CA...")
	err = createCA(outPath, sans, isUsingNameConstraints)
	if err != nil {
		log.Fatal("failed to create CA: ", err)
	}
	log.Println()

	log.Println("Creating server certificate...")
	err = createServerCert(outPath, sans)
	if err != nil {
		log.Fatal("failed to create server certificate: ", err)
	}
	log.Println()

	log.Println("Done!")
}

func createCA(outPath string, sans []string, isUsingNameConstraints bool) error {
	keyPath := filepath.Join(outPath, CA_KEY_FILE)
	if _, err := os.Stat(keyPath); err == nil {
		log.Println(keyPath + " already exists, skipping creation")
		return nil
	}

	key, err := rsa.GenerateKey(rand.Reader, KEY_SIZE)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	spec := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "create-local-cert CA for " + sans[0],
			Organization: []string{"create-local-cert CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	if isUsingNameConstraints {
		spec.PermittedDNSDomains = sans
		spec.PermittedDNSDomainsCritical = true
	}

	cert, err := x509.CreateCertificate(rand.Reader, &spec, &spec, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	err = writePEM(filepath.Join(outPath, CA_CERT_FILE), &pem.Block{Type: "CERTIFICATE", Bytes: cert}, CERT_FILE_MODE)
	if err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	err = writePEM(keyPath, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, KEY_FILE_MODE)
	if err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	return nil
}

func createServerCert(outPath string, sans []string) error {
	keyPath := filepath.Join(outPath, SERVER_KEY_FILE)
	if _, err := os.Stat(keyPath); err == nil {
		log.Println(keyPath + " already exists, skipping creation")
		return nil
	}

	caKeyPair, err := tls.LoadX509KeyPair(filepath.Join(outPath, CA_CERT_FILE), filepath.Join(outPath, CA_KEY_FILE))
	if err != nil {
		return fmt.Errorf("failed to load CA keypair: %w", err)
	}

	ca, err := x509.ParseCertificate(caKeyPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, KEY_SIZE)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	spec := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Issuer:       ca.Subject,
		Subject: pkix.Name{
			CommonName:   sans[0],
			Organization: []string{"create-local-cert"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:    sans,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &spec, ca, &key.PublicKey, caKeyPair.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	err = writePEM(filepath.Join(outPath, SERVER_CERT_FILE), &pem.Block{Type: "CERTIFICATE", Bytes: cert}, CERT_FILE_MODE)
	if err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	err = writePEM(keyPath, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, KEY_FILE_MODE)
	if err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	return nil
}

func writePEM(path string, block *pem.Block, mode os.FileMode) error {
	log.Printf("Writing %v with mode %v\n", path, mode)

	out, err := os.Create(path)
	if err != nil {
		log.Fatalf("file creation failed: %v", err)
	}
	defer out.Close()

	err = os.Chmod(path, mode)
	if err != nil {
		log.Fatalf("failed to set file permissions: %v", err)
	}

	err = pem.Encode(out, block)
	if err != nil {
		log.Fatalf("failed to write PEM block: %v", err)
	}

	return nil
}
