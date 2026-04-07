package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

func generateStorageKey() ([]byte, error) {
	saltPath := "storage_salt.bin"

	salt, err := os.ReadFile(saltPath)
	if err != nil {
		if os.IsNotExist(err) {

			salt = make([]byte, 16)
			_, err = rand.Read(salt)
			if err != nil {
				return nil, fmt.Errorf("Failed to generate salt: %v", err)
			}

			os.WriteFile(saltPath, salt, 0600)
		} else {
			return nil, fmt.Errorf("Failed to read salt file: %v", err)
		}
	}

	fmt.Println("Enter Master Password to unlock local files: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		return nil, fmt.Errorf("Failed to read password: %v", err)
	}

	localKey := pbkdf2.Key(password, salt, 100000, 32, sha256.New)
	return localKey, nil
}

func downloadAndSecure(filename string, plaintext []byte, localStorageKey []byte) error {
	ciphertext, err := encrypt(plaintext, localStorageKey, "SAVE_FILE")
	if err != nil {
		return fmt.Errorf("Failed to encrypt file for local storage: %v", err)
	}

	fileDir := "FileStorage"
	os.MkdirAll(fileDir, 0755)

	fullpath := filepath.Join(fileDir, filename)
	err = os.WriteFile(fullpath, ciphertext, 0600)
	if err != nil {
		return fmt.Errorf("Failed to write encrypted file to local storage: %v", err)
	}

	return nil
}

func loadSecureFile(filename string, localStorageKey []byte) ([]byte, error) {

	fileDir := "FileStorage"
	fullpath := filepath.Join(fileDir, filename)

	ciphertext, err := os.ReadFile(fullpath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file from disk: %v", err)
	}

	plaintext, err := decrypt(ciphertext, localStorageKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt file '%s' from storage: %v", filename, err)
	}

	return plaintext, nil

}

func importFiles(localStorageKey []byte) {

	files, _ := getFilesList("ImportFiles")
	if len(files) == 0 {
		fmt.Println("There are no files in the 'ImportFiles' directory.")
		return
	}

	for _, f := range files {
		safePath := filepath.Clean(f)
		fullpath := filepath.Join("ImportFiles", safePath)

		plaintext, err := os.ReadFile(fullpath)
		if err != nil {
			fmt.Printf("\nFailed to read file from disk: %v\n", err)
			return
		}
		signedData, err := signData(plaintext)
		err = downloadAndSecure(safePath, signedData, localStorageKey)
		if err != nil {
			fmt.Printf("\nFailed to import file '%s' to File Storage\n", safePath)
			return
		}
	}
}

func exportFile(filename string, localStorageKey []byte) {

	fileBytes, err := loadSecureFile(filename, localStorageKey)
	if err != nil {
		fmt.Printf("\n%v", err)
	}

	cleanData, err := verifyData(fileBytes)

	fullpath := filepath.Join("ImportFiles", filename)

	err = os.WriteFile(fullpath, cleanData, 0644)
	if err != nil {
		log.Fatalf("Failed to export file '%s': %v", filename, err)
	}

	fmt.Printf("\nSuccessfuly decrypted and exported file '%s' to folder 'ImportFiles'\n", filename)

}
