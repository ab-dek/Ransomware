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

func main() {
	dec := flag.NewFlagSet("dec", flag.ExitOnError)
	prikey := dec.String("k", "", "private key")
	ciph := dec.String("v", "", "cipher text")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n./rsa_tool gen\n\tGenerate RSA key pairs\n./rsa_tool dec -k <privatekey> -v <ciphertext>\n\tDecrypt ciphertext using the specified private key\n")
	}

	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Println("no argument provided")
		flag.Usage()
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
		publicKey, err := pubkeyToPEM(&privateKey.PublicKey)
		if err != nil {
			log.Fatalf("Failed to encode public key: %v", err)
		}
		priKeyEncoded, err := privkeyToPEM(privateKey)
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
		fmt.Println("\nDecrypting the key...")
		prikeyDec, err := privkeyFromPEM(*prikey)
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
		fmt.Println("key:", string(decryptedBytes))

	default:
		fmt.Println(os.Args[1], "unknown command")
		flag.Usage()
		os.Exit(1)
	}
}

func pubkeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	var pemBuffer bytes.Buffer
	err = pem.Encode(&pemBuffer, pemBlock)
	if err != nil {
		return "", err
	}

	return pemBuffer.String(), nil
}

func privkeyToPEM(privateKey *rsa.PrivateKey) (string, error) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}
	var pemBuffer bytes.Buffer
	err := pem.Encode(&pemBuffer, pemBlock)
	if err != nil {
		return "", err
	}

	return pemBuffer.String(), nil
}

func privkeyFromPEM(privateKeyPEM string) (*rsa.PrivateKey, error) {
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
		return nil, err
	}

	return privateKey, nil
}
func decryptRSA(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	oaepHash := sha256.New()

	plaintext, err := rsa.DecryptOAEP(oaepHash, rand.Reader, privateKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

