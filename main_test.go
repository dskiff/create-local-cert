package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateCA(t *testing.T) {
	outPath := t.TempDir()
	sans := []string{"example.com"}
	isUsingNameConstraints := true

	err := createCA(outPath, sans, isUsingNameConstraints)
	if err != nil {
		t.Fatalf("createCA failed: %v", err)
	}

	certPath := filepath.Join(outPath, CA_CERT_FILE)
	keyPath := filepath.Join(outPath, CA_KEY_FILE)

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("CA certificate not found at %v", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("CA key not found at %v", keyPath)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read CA certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode CA certificate PEM")
	}

	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
}

func TestCreateServerCert(t *testing.T) {
	outPath := t.TempDir()
	sans := []string{"example.com"}

	err := createCA(outPath, sans, true)
	if err != nil {
		t.Fatalf("createCA failed: %v", err)
	}

	err = createServerCert(outPath, sans)
	if err != nil {
		t.Fatalf("createServerCert failed: %v", err)
	}

	certPath := filepath.Join(outPath, SERVER_CERT_FILE)
	keyPath := filepath.Join(outPath, SERVER_KEY_FILE)

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("Server certificate not found at %v", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("Server key not found at %v", keyPath)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read server certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode server certificate PEM")
	}

	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse server certificate: %v", err)
	}
}
