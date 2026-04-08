package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
)

// Helper function
func generateTestSessionKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

// Function to test if encryption and decryption maintain integrity
func Test_EncryptionDecryption(t *testing.T) {

	//Create a test session key and test data
	sessionKey := generateTestSessionKey()
	testData := []byte("Hello, World.")

	//Encrypt
	ciphertext, err := encrypt(testData, sessionKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	//Ciphertext should be longer (nonce + mac tag)
	if len(ciphertext) <= len(testData) {
		t.Errorf("Ciphertext was not longer than plaintext. Length: %d", len(ciphertext))
	}

	//Decrypt
	plaintext, err := decrypt(ciphertext, sessionKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	//Check if decryption was corrupted
	if !bytes.Equal(plaintext, testData) {
		t.Errorf("Decrypted data does not match original data")
	}
}

// Function to test if decryption will detect file tampering
func TestAES_Tampering(t *testing.T) {

	//Dummy data
	sessionKey := generateTestSessionKey()
	testData := []byte("Hello, World.")

	//Encrypt
	ciphertext, _ := encrypt(testData, sessionKey)

	//Simulate man in the middle attack; changing a single bit
	ciphertext[len(ciphertext)-1] ^= 0xFF

	//Decrypt should now throw an error
	_, err := decrypt(ciphertext, sessionKey)
	if err == nil {
		t.Errorf("Test failed. Decryption did not throw error")
	}
}

// Function to test digital signature verification
func TestSignature_Verification(t *testing.T) {

	//Load private and public identity keys
	privPath := "identity_priv.pem"
	pubPath := "identity_pub.pem"
	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		createIdentity(privPath, pubPath)
	}
	_, pubKey, _ := loadIdentity(privPath, pubPath)

	//Save ourselves as a contact for testing
	os.MkdirAll("contacts", 0755)
	saveContact(pubKey)

	//Create dummy data
	testData := []byte("Hello, World!")

	//Sign the dummy data
	signedData, err := signData(testData)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	//The signed data should be exactly 76-bytes longer than the test data
	if len(signedData) != len(testData)+76 {
		t.Errorf("Signed data length incorrect. Expected %d bytes, got %d", len(testData)+76, len(signedData))
	}

	//Verify the signed data
	cleanData, err := verifyData(signedData)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	//Ensure that the signed data is equal to the original after verification
	if !bytes.Equal(cleanData, testData) {
		t.Errorf("Cleaned data does not match original test data")
	}
}

// Function to test protection against file tampering
func TestSignature_Tampering(t *testing.T) {

	//Create dummy data
	testData := []byte("Hello, World!")
	signedData, _ := signData(testData)

	//Change one byte in signed data; Simulating man-in-middle attack
	signedData[0] ^= 0xFF

	//Verify the data; it should throw an error
	_, err := verifyData(signedData)
	if err == nil {
		t.Errorf("Expected verification to fail to due tampering, however it succeeded...")
	}
}

// Function to test protection against files with unknown authors
func TestUnknown_Signature(t *testing.T) {

	//Create dummy data
	testData := []byte("Hello, Prof!")
	signedData, _ := signData(testData)

	//Change the 12-byte fingerprint to an unknown author
	//*All 0-bytes
	splitIdx := len(signedData) - 76
	for i := 0; i < 12; i++ {
		signedData[splitIdx+i] = '0'
	}

	//Attempt to verify data
	//Err should != nil as verification should fail
	_, err := verifyData(signedData)
	if err == nil {
		t.Errorf("Expected verification to fail due to unknown author, but it succeeded...")
	}
}
