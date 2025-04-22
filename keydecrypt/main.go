package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
)

func encodePublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("error marshalling public key to DER format: %w", err)
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	var pemBuffer bytes.Buffer
	err = pem.Encode(&pemBuffer, pemBlock)
	if err != nil {
		return "", fmt.Errorf("error encoding PEM block: %w", err)
	}

	return pemBuffer.String(), nil
}

func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) (string, error) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}
	var pemBuffer bytes.Buffer
	err := pem.Encode(&pemBuffer, pemBlock)
	if err != nil {
		return "", fmt.Errorf("error encoding private key PEM block: %w", err)
	}

	return pemBuffer.String(), nil
}

func decodePrivateKeyFromPEM(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	if len(rest) > 0 {
		log.Printf("Warning: Trailing data found after PEM block")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type: expected 'RSA PRIVATE KEY', got '%s'", block.Type)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#1 private key: %w", err)
	}

	return privateKey, nil
}
func decryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	oaepHash := sha256.New()

	plaintext, err := rsa.DecryptOAEP(oaepHash, rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting number: %w", err)
	}
	return plaintext, nil
}

func main() {
	dec := flag.NewFlagSet("dec", flag.ExitOnError)
	prikey := dec.String("k", "", "private key")
	ciph := dec.String("v", "", "cipher text")

	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Println("TODO: create and print flag usage")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "gen":
		fmt.Println("Generating 2048-bit RSA key pair...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}
		fmt.Println("Key pair generated successfully.")
		fmt.Println("Encoding RSA key pair...")
		publicKey, err := encodePublicKeyToPEM(&privateKey.PublicKey)
		if err != nil {
			log.Fatalf("Failed to encode public key: %v", err)
		}
		priKeyEncoded, err := encodePrivateKeyToPEM(privateKey)
		if err != nil {
			log.Fatalf("Failed to encode private key: %v", err)
		}

		fmt.Println("public key:", publicKey)
		fmt.Println("private key:", priKeyEncoded)

	case "dec":
		dec.Parse(os.Args[2:])
		if *prikey == "" && *ciph == "" {
			fmt.Println("Error: value/s not provided")
			os.Exit(1)
		}
		fmt.Println("\nDecrypting the number...")
		prikeyDec, err := decodePrivateKeyFromPEM(*prikey)
		if err != nil {
			log.Fatalf("Failed to decode private key: %v", err)
		}
		ciphDec, err := base64.StdEncoding.DecodeString(*ciph)
		if err != nil {
			log.Fatalf("Failed to decode the cipher: %v", err)
		}
		decryptedBytes, err := decryptRSA(prikeyDec, []byte(ciphDec))
		if err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}
		fmt.Println("cipher text:", string(decryptedBytes))

	default:
		fmt.Println(os.Args[1], "unknown command")
		fmt.Println("TODO: create and print flag usage")
		os.Exit(1)
	}
}


