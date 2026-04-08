package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Define the structure of a message
type message struct {
	Action   string   `json:"action"`   //Define how the program will handle the message
	Filename string   `json:"filename"` //Define the filename or status; if message contains a file
	Payload  []byte   `json:"payload"`  //Define the payload; Contains the plaintext
	FileList []string `json:"filelist"` //Define the filelist; Contains list of peers files
}

// Create two sync maps to hold pending requests
var pendingDownloads sync.Map
var pendingUploads sync.Map

// Helper function to ask for client consent
func getConsent() bool {

	//Initialize the response string
	var response string

	for {
		//Read the response from stdin
		fmt.Scan(&response)

		//Switch case to handle response
		switch response {

		//If answer is 'y'.lower() or "", return true; client consented
		case "y", "Y", "":
			return true

		//If answer is 'n'.lower(), return false; client rejected request
		case "n", "N":
			return false

		//Handle non-meaningful responses
		default:
			fmt.Println("Please answer with either y/n.")
		}
	}

}

// UI For handling requests on client side
func handleOutbound(conn net.Conn, sessionKey []byte, storageKey []byte, peerName string) {

	//Create a scanner to read stdin
	scanner := bufio.NewScanner(os.Stdin)

	//Display list of available commands
	fmt.Println("\nAvailable commands:")
	fmt.Println("\t- 'list' for peer's filelist\n\t- 'get <filename>' for requests\n\t- 'send <filename>' to send")
	fmt.Println("\t- 'exit' or 'quit' to close the menu.")

	//Infinite loop; Unless user exits or quits
	for {

		//Format the terminal for user input
		fmt.Printf("")
		fmt.Printf("\t<%s --- cmd> ", peerName)
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())

		//Split response into arguments; space separated
		args := strings.Split(input, " ")

		//First word is the command
		command := args[0]

		switch command {

		//Handles user requesting a peers 'list'
		case "list":
			//Create REQ_LIST message and send
			msg := message{Action: "REQ_LIST"}
			err := sendMessage(conn, msg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending request for peer list: %v\n", err)
				continue
			}

			//Prompt user of successful request
			fmt.Println("Request for peer's file list has been sent! Awaiting response...")

			//Reprint command prompt
			fmt.Printf("\t<%s --- cmd> ", peerName)

		//Handle user requesting a peer's file
		case "get":

			//Ensure they included a filename
			if len(args) < 2 {
				//Otherwise prompt and continue to next command prompt
				fmt.Println("Usage: get <filename>")
				continue
			}

			//Create the request message for desired file and send
			msg := message{Action: "REQ_FILE", Filename: args[1]}
			err := sendMessage(conn, msg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending request for file '%s': %v\n", msg.Filename, err)
				continue
			}

			//Prompt user of success
			fmt.Printf("Request for file '%s' has been sent! Awaiting response...\n", msg.Filename)

		//Handle user sending a file from their local storage
		case "send":

			//Ensure they included a filename
			if len(args) < 2 {
				fmt.Println("Usage: send <filename>")
				continue
			}

			//Clean the filepath; avoids path traversal attacks
			safePath := filepath.Clean(args[1])
			//Load the file bytes from the secure local storage
			fileBytes, err := loadSecureFile(safePath, storageKey)
			//Handle reading error
			if err != nil {
				fmt.Printf("Error reading file '%s': %v\n", safePath, err)
				continue
			}

			//Sign the data
			signedData, err := signData(fileBytes)
			if err != nil {
				fmt.Printf("Error signing file: %v\n", err)
				continue
			}

			//Encapsulate in message
			msg := message{
				Action:   "SEND_FILE",
				Filename: safePath,
				Payload:  signedData,
			}

			//Send the message and handle errors
			err = sendMessage(conn, msg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending file '%s': %v\n", msg.Filename, err)
				continue
			}

			//Prompt the user of success
			fmt.Printf("File '%s' has been sent to peer for approval!\n", msg.Filename)

		//Handles a user accepting a file sent without prior request
		case "accept":

			//Ensure filename is given
			if len(args) < 2 {
				fmt.Printf("Usage: accept <filename>")
				continue
			}
			filename := args[1]

			//Load the file from the download queue
			payloadInterface, exists := pendingDownloads.Load(filename)
			//Handle if the file is not in the queue
			if !exists {
				fmt.Printf("No pending download for '%s'.\n", filename)
			}

			//Convert the file from the queue into a stream of bytes
			payload := payloadInterface.([]byte)
			//Delete the file from queue once fetched
			pendingDownloads.Delete(filename)

			//Verify its digital signature
			_, err := verifyData(payload)
			//Handle file tampering
			if err != nil {
				fmt.Printf("\n[!] CRITICAL: %v\n", err)
				fmt.Println("Dropping tampered file.")
				continue
			}

			//Download the file and securely store to local storage
			err = downloadAndSecure(filename, payload, storageKey)
			if err != nil {
				fmt.Printf("[!] Error downloading file '%s': %v\n", filename, err)
				continue
			}

			//Prompt user of success
			fmt.Printf("Successfully downloaded '%s' to FileStorage!\n", filename)

		//Handle user rejecting a sent file
		case "reject":

			//Ensure filename was passed in
			if len(args) < 2 {
				fmt.Println("Usage: reject <filename>")
				continue
			}
			filename := args[1]

			//Delete the file from the queue and prompt user
			pendingDownloads.Delete(filename)
			fmt.Printf("File %s has been rejected.\n", filename)

		//Handle the user approving a file request from a peer
		case "approve":

			//Ensure a filename was passed
			if len(args) < 2 {
				fmt.Println("Usage: approve <filename>")
				continue
			}
			filename := args[1]

			//Ensure the file exists in the upload queue
			_, exists := pendingUploads.Load(filename)
			//If not, prompt user
			if !exists {
				fmt.Printf("No pending request for file %s.\n", filename)
				continue
			}

			//Clean filepath
			safePath := filepath.Clean(filename)
			fullpath := filepath.Join("FileStorage", safePath)

			//Check if the file exists in storage; if not, prompt user and send NOT_FOUND message to peer
			if _, err := os.Stat(fullpath); err != nil {
				fmt.Printf("File '%s' does not exist. Notifying peer...\n", safePath)
				denialMsg := message{Action: "RES_FILE", Filename: filename, FileList: []string{"NOT_FOUND"}}
				sendMessage(conn, denialMsg, sessionKey)
				pendingUploads.Delete(filename)
				continue
			}

			//Load the file from the secure local storage
			fileBytes, err := loadSecureFile(safePath, storageKey)
			//Handle errors
			if err != nil {
				fmt.Printf("Error loading file '%s' from storage: %v", filename, err)
				pendingUploads.Delete(filename)
				continue
			}

			//Sign the data from the file
			signedData, err := signData(fileBytes)
			if err != nil {
				fmt.Printf("Error signing file: %v\n", err)
				pendingUploads.Delete(filename)
				continue
			}

			//Encapsulate data in a message
			responseMsg := message{
				Action:   "RES_FILE",
				Filename: filename,
				Payload:  signedData,
			}

			//Send said message and handle errors
			err = sendMessage(conn, responseMsg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending message: %v", err)
				continue
			}

			//Prompt the user of success and delete filename from upload queue
			fmt.Printf("File '%s' has been approved and is being sent to peer\n", filename)
			pendingUploads.Delete(filename)

		//Handle the user denying a file request
		case "deny":

			//Ensure a filename was given
			if len(args) < 2 {
				fmt.Println("Usage: deny <filename>")
				continue
			}
			filename := args[1]

			//If the file doesn't exist in the queue, prompt user and continue
			_, exists := pendingUploads.Load(filename)
			if !exists {
				fmt.Printf("No pending file request for '%s'\n", filename)
				continue
			}

			//Create denial message and send
			denialMsg := message{
				Action:   "RES_FILE",
				Filename: filename,
				FileList: []string{"DENIED"},
			}
			sendMessage(conn, denialMsg, sessionKey)

			//Delete file from queue and prompt user
			pendingUploads.Delete(filename)
			fmt.Printf("Rejected request for file '%s'\n", filename)

		//Allow the user to exit this interface to go back to the main menu
		case "exit", "quit":
			fmt.Println("Leaving peer session...")
			return

		default:
			//Prompt user unknown command; reprint available commands
			fmt.Println("\nUnknown command. Available commands:")
			fmt.Println("\t- 'list' for peer's filelist\n\t- 'get <filename>' for requests\n\t- 'send <filename>' to send")
			fmt.Println("\t- 'exit' or 'quit' to close the menu.")
		}
	}

}

// Will be called with go so that it operates in the background checking for requests
func handleInbound(conn net.Conn, sessionKey []byte, storageKey []byte, peerID string, peerName string) {

	//Forever loop; Used to constantly check the tcp tunnel
	for {

		//Get the message from the TCP tunnel; Will block rest of the function until a msg is received
		msg, err := decodeMessage(conn, sessionKey)
		if err != nil {
			fmt.Printf("\n[!] Error decoding peer's payload: %v\n", err)
			continue
		}

		//Determine the request type
		switch msg.Action {

		//Handle the peer requesting our file list
		case "REQ_LIST":

			//Fetch list of available files
			files, _ := getFilesList("FileStorage")

			//Package into a message struct
			responseMsg := message{
				Action:   "RES_LIST",
				FileList: files,
			}

			//Call sendMessage to: marshal the struct into json; encrypt the json message;
			//send the size of the encrypted message with the message itself
			err = sendMessage(conn, responseMsg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending message: %v", err)
				continue
			}

			//Prompt the user of success
			fmt.Println("List of available files has been sent to peer!")
			fmt.Printf("\t<%s --- cmd> ", peerName)

		//Handle the peer requesting a file
		case "REQ_FILE":

			//Alert client that Peer has requested a file
			fmt.Printf("\n\n[ALERT] Peer %s is requesting file '%s'.\n", peerName, msg.Filename)
			fmt.Printf("\tType 'approve %s' or 'deny %s' to respond.\n", msg.Filename, msg.Filename)

			//Reprint command prompt
			fmt.Printf("\t<%s --- cmd> ", peerName)

			//Add requested file to the upload queue
			pendingUploads.Store(msg.Filename, true)

		//Handle the peer responding with their file list
		case "RES_LIST":

			//Header
			fmt.Printf("\n--- %s Available Files ---\n", peerName)

			//Prompt the user if the file list is empty
			if len(msg.FileList) == 0 {
				fmt.Println("- (Peer has shared no files or has none)")

			} else {
				//Otherwise define filepath to peer's list
				filename := fmt.Sprintf("peer_%s.txt", peerID)
				fullpath := filepath.Join("peerLists", filename)

				//Create peer list file
				file, err := os.Create(fullpath)
				if err != nil {
					fmt.Printf("Error creating peer's file list: %v\n", err)
				}

				//Iterate through each filename in the list; print to user
				for _, filename := range msg.FileList {
					fmt.Println("-" + filename)

					//If the file was created; save each line
					if file != nil {
						file.WriteString(filename + "\n")
					}
				}
				//Prompt user if the list is save-able
				if file != nil {
					fmt.Printf("Peer's file list has been saved to '%s'\n", fullpath)
				}
				//Reprint command prompt
				fmt.Printf("\t<%s --- cmd> ", peerName)
			}

		//Handle the peer responding with a requested file
		case "RES_FILE":

			//We will receive the status of the request response in the filelist
			if len(msg.FileList) > 0 {
				status := msg.FileList[0]

				//If the request was denied, prompt the user
				if status == "DENIED" {
					fmt.Printf("\n[!] Peer has denied your request for file '%s'\n", msg.Filename)
					continue

					//If the file was not found, prompt the user
				} else if status == "NOT_FOUND" {
					fmt.Printf("\n[!] Peer does not have the file '%s'\n", msg.Filename)
					continue
				}
			}

			//Verify the signature of the payload
			_, err := verifyData(msg.Payload)
			//Handle file tampering
			if err != nil {
				fmt.Printf("[!] CRITICAL: %v\n", err)
				fmt.Printf("[!] Dropping tampered file '%s'.\n", msg.Filename)
				continue
			}

			//Prompt user of success and begin downloading file securely
			fmt.Printf("Request for file '%s' approved! Downloading...\n", msg.Filename)
			downloadAndSecure(msg.Filename, msg.Payload, storageKey)

			//Reprint command prompt
			fmt.Printf("\t<%s --- cmd> ", peerName)

		//Handle the peer sending a file without it being requested
		case "SEND_FILE":

			//Alert the client that a file has been sent to them
			fmt.Printf("\n\n[PEER ALERT] Peer %s has sent you file '%s'.\n", peerName, msg.Filename)
			fmt.Printf("\tType 'accept %s' or 'reject %s' to respond.\n", msg.Filename, msg.Filename)
			//Store file in the download queue
			pendingDownloads.Store(msg.Filename, msg.Payload)

			//Reprint command prompt
			fmt.Printf("\t<%s --- cmd> ", peerName)

		//Handle if a peer migrates to a new key
		case "KEY_MIGRATION":

			//Prompt user of compromise
			fmt.Printf("\n[!] CRITICAL: Peer '%s' has migrated their key. Repairing contact...\n", peerName)

			//Define new public key for peer
			newKey := msg.Payload
			//Define their old contact
			oldFilename := fmt.Sprintf("peer_%s.pem", peerID)
			oldFilepath := filepath.Join("contacts", oldFilename)

			//Delete the old contact
			err := os.Remove(oldFilepath)
			//If there is an error or the contact doesn't exist, prompt the user
			if err != nil && !os.IsNotExist(err) {
				fmt.Printf("Failed to delete compromised contact %s: %v", oldFilename, err)
				continue
			}

			//Save new key as a contact
			_, err = saveContact(newKey)
			if err != nil {
				fmt.Printf("Failed to store new key: %v\n", err)
			}

			//Prompt successful migration
			fmt.Printf("Deleted compromised contact: %s\n", oldFilename)

			fmt.Printf("\t<%s --- cmd> ", peerName)

		}

	}
}

// Function to encrypt a stream of bytes in AES-GCM mode
func encrypt(plaintext []byte, sessionKey []byte) ([]byte, error) {

	//Create a new cipher block using the session key
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	//Create a new GCM block
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	//Create a nonce for encryption
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	//Create the ciphertext using AES-GCM and a nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	//Return ciphertext back to client
	return ciphertext, nil
}

// Function to decrypt a stream of bytes in AES-GCM mode
func decrypt(ciphertext []byte, sessionKey []byte) ([]byte, error) {

	//Create a cipher block
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	//Create the GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	//Create a nonce and ensure the ciphertext is atleast longer than it
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("Ciphertext is too short")
	}

	//Separate the nonce from the ciphertext
	nonce, realCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	//Create the plaintext using GCM decryption
	plaintext, err := gcm.Open(nil, nonce, realCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed; possible tampering: %v", err)
	}

	//Return plaintext bytes
	return plaintext, nil
}

// Helper function to fetch the list of available files from client's storage
func getFilesList(fileDir string) ([]string, error) {

	//Pull the entries from the file directory
	entries, err := os.ReadDir(fileDir)
	if err != nil {
		return nil, fmt.Errorf("Error fetching files: %v", err)
	}
	//Define return list
	var files []string

	//Iterate through each entry and add filename to files list
	for _, e := range entries {
		files = append(files, e.Name())
	}

	//Return list of files
	return files, nil
}

// Helper function that solely send a message struct as an encrypted stream of bytes
func sendMessage(conn net.Conn, msg message, sessionKey []byte) error {

	//Marshal the msg to format to json
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	//Encrypt the json data
	ciphertext, err := encrypt(data, sessionKey)
	if err != nil {
		return err
	}

	//Define the payload size in Uint32
	payloadSize := uint32(len(ciphertext))
	prefixBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(prefixBuf, payloadSize)

	//Send the size of the payload, then the payload
	conn.Write(prefixBuf)
	conn.Write(ciphertext)

	return nil
}

// helper function to read connection and decrypt payload into message struct
func decodeMessage(conn net.Conn, sessionKey []byte) (message, error) {

	//Initialize the message
	var msg message

	//Fetch the size of the payload first
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, sizeBuf); err != nil {
		return msg, nil
	}

	//Convert size into a uint32
	msgSize := binary.BigEndian.Uint32(sizeBuf)

	//Read the rest of the connection to pull the ciphertext
	ciphertext := make([]byte, msgSize)
	if _, err := io.ReadFull(conn, ciphertext); err != nil {
		return msg, fmt.Errorf("Failed to read payload: %v", err)
	}

	//Decrypt the ciphertext into plaintext
	plaintext, err := decrypt(ciphertext, sessionKey)
	if err != nil {
		return msg, err
	}

	//Trim null terminating bytes from plaintext stream
	plaintext = bytes.Trim(plaintext, "\x00")
	//Unmarshal bytestream into message struct
	err = json.Unmarshal(plaintext, &msg)
	if err != nil {
		return msg, fmt.Errorf("Failed to encode plaintext to message format: %v", err)
	}

	//Return decoded message or empty message
	return msg, nil
}

// Helper function to load a peer's public
func loadPublicKey(fingerprintHex string) (ed25519.PublicKey, error) {

	//define contact path
	filename := fmt.Sprintf("peer_%s.pem", fingerprintHex)
	fullpath := filepath.Join("contacts", filename)

	//Read bytes if peer exists
	fileBytes, err := os.ReadFile(fullpath)
	if err != nil {
		return nil, fmt.Errorf("Unrecognized peer: %v", err)
	}

	//Decode the pem of the peer's public key
	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("Failed to parse PEM blocks in file '%s'", filename)
	}

	//Ensure the block is a 'Peer Public Key'
	if block.Type != "Peer Public Key" {
		return nil, fmt.Errorf("invalid PEM type: Expected 'Peer Public Key', got %s", block.Type)
	}

	//Return public key in ed25519 format
	return ed25519.PublicKey(block.Bytes), nil
}

// Helper function to sign data stream
func signData(data []byte) ([]byte, error) {

	//Load client's private and public keys
	privKey, pubKey, err := loadIdentity("identity_priv.pem", "identity_pub.pem")
	if err != nil {
		return nil, fmt.Errorf("Critical error loading keys: %v", err)
	}

	//Create a hash & signature
	hash := sha256.Sum256(data)
	signature := ed25519.Sign(privKey, hash[:])

	//Create a fingerprint based on the first 12 bytes of hashed public key
	pubHash := sha256.Sum256(pubKey)
	fingerprintHex := hex.EncodeToString(pubHash[:])[:12]

	//Create a bundle payload to return the data with a digital signature (fingerprint + signature)
	bundle := make([]byte, 0, len(data)+76)
	bundle = append(bundle, data...)
	bundle = append(bundle, []byte(fingerprintHex)...)
	bundle = append(bundle, signature...)

	//Return payload
	return bundle, nil
}

// Helper function used to verify a digital signature
func verifyData(data []byte) ([]byte, error) {

	//Ensure the payload is atleast the size of a signature (76-bytes)
	if len(data) < 76 {
		return nil, fmt.Errorf("File is too small to contain a signature")
	}

	//Split data into plaintext and the tail (fingerprint + signature)
	splitIdx := len(data) - 76
	plaintext := data[:splitIdx]
	tail := data[splitIdx:]

	//Define the fingerprint and signature
	fingerprintBytes := tail[:12]
	signature := tail[12:]

	fingerprintHex := string(fingerprintBytes)
	hash := sha256.Sum256(plaintext)

	//Load the peer's public key from contacts
	pubKey, err := loadPublicKey(fingerprintHex)
	//Handle unknown signature
	if err != nil {
		return nil, fmt.Errorf("Unknown signature '%s': %v", fingerprintHex, err)
	}

	//Ensure data is not compromised
	isValid := ed25519.Verify(pubKey, hash[:], signature)
	if !isValid {
		//Prompt user if file is tampered
		return nil, fmt.Errorf("FILE VERIFICATION FAILED: File has been tampered with")
	}

	//Otherwise return the verified data, if needed
	return plaintext, nil
}
