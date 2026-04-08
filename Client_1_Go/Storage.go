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

// Function to generate/pull the client's storage key; used to access their encrypted files
func generateStorageKey() ([]byte, error) {

	//Define path to key
	saltPath := "storage_salt.bin"

	//Attempt to read file
	salt, err := os.ReadFile(saltPath)
	if err != nil {

		//If the file does not exist; New user!
		//Must initialize the master password & salt
		if os.IsNotExist(err) {

			//Generate a random 16-byte salt
			salt = make([]byte, 16)
			_, err = rand.Read(salt)
			if err != nil {
				return nil, fmt.Errorf("Failed to generate salt: %v", err)
			}

			//Save the salt; w/r access only for owner
			os.WriteFile(saltPath, salt, 0600)
		} else {
			return nil, fmt.Errorf("Failed to read salt file: %v", err)
		}
	}

	//Check for the client's master password
	fmt.Println("Enter Master Password to unlock local files: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		return nil, fmt.Errorf("Failed to read password: %v", err)
	}

	//Generate the storage key given the password and salt
	//100,000 iterations for added security
	localKey := pbkdf2.Key(password, salt, 100000, 32, sha256.New)
	return localKey, nil
}

// Function to download and secure a file to local storage
func downloadAndSecure(filename string, plaintext []byte, localStorageKey []byte) error {

	//Encrypt the plaintext with our storage key
	ciphertext, err := encrypt(plaintext, localStorageKey)
	if err != nil {
		return fmt.Errorf("Failed to encrypt file for local storage: %v", err)
	}

	//Ensure FileStorage exists
	fileDir := "FileStorage"
	os.MkdirAll(fileDir, 0755) // w/r/x for owner; r/x for everyone else

	//Download the encrypted file to secure storage
	fullpath := filepath.Join(fileDir, filename)
	err = os.WriteFile(fullpath, ciphertext, 0600)
	if err != nil {
		return fmt.Errorf("Failed to write encrypted file to local storage: %v", err)
	}

	return nil
}

// Function to load an encrypted file from local storage
func loadSecureFile(filename string, localStorageKey []byte) ([]byte, error) {

	//Define file path
	fileDir := "FileStorage"
	fullpath := filepath.Join(fileDir, filename)

	//Read the encrypted file from storage
	ciphertext, err := os.ReadFile(fullpath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file from disk: %v", err)
	}

	//Decrypt it using the storage key
	plaintext, err := decrypt(ciphertext, localStorageKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt file '%s' from storage: %v", filename, err)
	}

	//Return the unencrypted file
	return plaintext, nil

}

// Helper function to import all unencrypted files to secure storage
func importFiles(localStorageKey []byte) {

	//Get list of files in 'Import' Folder
	files, _ := getFilesList("ImportFiles")

	//Ensure there are items in the directory
	if len(files) == 0 {
		fmt.Println("There are no files in the 'ImportFiles' directory.")
		return
	}

	//Iterate through each filename in the directory
	for _, f := range files {

		//Clean the path to avoid traversal attacks
		safePath := filepath.Clean(f)
		fullpath := filepath.Join("ImportFiles", safePath)

		//Read the current file from Imports
		plaintext, err := os.ReadFile(fullpath)
		if err != nil {
			fmt.Printf("\nFailed to read file from disk: %v\n", err)
			return
		}

		//sign the plaintext with digital signature
		signedData, err := signData(plaintext)

		//Downloaded & encrypt the signed data
		err = downloadAndSecure(safePath, signedData, localStorageKey)
		if err != nil {
			fmt.Printf("\nFailed to import file '%s' to File Storage\n", safePath)
			return
		}
	}
}

// Helper function to export a desired file from encrypted storage
func exportFile(filename string, localStorageKey []byte) {

	//Load & decrypt the file from secure storage
	fileBytes, err := loadSecureFile(filename, localStorageKey)
	if err != nil {
		fmt.Printf("\n%v", err)
	}

	//Verify the signature of the file first
	cleanData, err := verifyData(fileBytes)

	//If clean, download the unencrypted file back to 'Import' folder
	fullpath := filepath.Join("ImportFiles", filename)
	err = os.WriteFile(fullpath, cleanData, 0644)
	if err != nil {
		log.Fatalf("Failed to export file '%s': %v", filename, err)
	}

	//Prompt user of success
	fmt.Printf("\nSuccessfuly decrypted and exported file '%s' to folder 'ImportFiles'\n", filename)

}
