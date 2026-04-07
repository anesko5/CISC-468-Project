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
)

type message struct {
	Action   string   `json:"action"`
	Filename string   `json:"filename"`
	Payload  []byte   `json:"payload"`
	FileList []string `json:"filelist"`
}

func getConsent() bool {
	response := "x"

	for {
		fmt.Scan(&response)
		response = strings.ToLower(response)

		switch response {
		case "y", "Y", "":
			return true
		case "n", "N":
			return false
		default:
			fmt.Println("Please answer with either y/n.")
		}
	}

}

func handleOutbound(conn net.Conn, sessionKey []byte, storageKey []byte) {

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Printf("")
		fmt.Print("cmd> ")
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		args := strings.Split(input, " ")
		command := args[0]

		switch command {
		case "list":
			msg := message{Action: "REQ_LIST"}
			err := sendMessage(conn, msg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending request for peer list: %v\n", err)
				continue
			}
			fmt.Println("Request for peer's file list has been sent! Awaiting response...")
		case "get":
			if len(args) < 2 {
				fmt.Println("Usage: get <filename>")
				continue
			}
			msg := message{Action: "REQ_FILE", Filename: args[1]}
			err := sendMessage(conn, msg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending request for file '%s': %v\n", msg.Filename, err)
				continue
			}
			fmt.Printf("Request for file '%s' has been sent! Awaiting response...\n", msg.Filename)
		case "send":
			if len(args) < 2 {
				fmt.Println("Usage: send <filename>")
				continue
			}

			safePath := filepath.Clean(args[1])
			fileBytes, err := loadSecureFile(safePath, storageKey)
			if err != nil {
				fmt.Printf("Error reading file '%s': %v\n", safePath, err)
				continue
			}

			msg := message{
				Action:   "SEND_FILE",
				Filename: safePath,
				Payload:  fileBytes,
			}
			err = sendMessage(conn, msg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending file '%s': %v\n", msg.Filename, err)
				continue
			}
			fmt.Printf("File '%s' has been sent to peer for approval!\n", msg.Filename)

		case "exit", "quit":
			fmt.Println("Leaving peer session...")
			return

		default:
			fmt.Println("Unknown command. Available commands: 'list', 'get <filename>', 'send <filename>'")
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
			files, _ := getFilesList("myFiles")

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

		//Handle the peer requesting a file
		case "REQ_FILE":

			//Clean the path; Do this to avoid directory traversal attacks
			safePath := filepath.Clean(msg.Filename)
			fullPath := filepath.Join("myFiles", safePath)

			//Get consent from the user to send the file
			fmt.Printf("[CONSENT REQUIRED] Allow peer %s to download file '%s'? (Y/n): ", peerName, msg.Filename)
			//If the user does not consent, continue to the next read of the tcp tunnel
			if !getConsent() {
				fmt.Println("Request denied.")
				denialMsg := message{Action: "RES_FILE", Filename: msg.Filename, FileList: []string{"DENIED"}}
				sendMessage(conn, denialMsg, sessionKey)
				continue
			}

			if _, err := os.Stat(fullPath); err != nil {
				fmt.Printf("File '%s' does not exist in your available files. Notifying peer...\n", safePath)
				denialMsg := message{Action: "RES_FILE", Filename: msg.Filename, FileList: []string{"NOT_FOUND"}}
				sendMessage(conn, denialMsg, sessionKey)
			}

			//Read the entire file
			fileBytes, err := loadSecureFile(safePath, storageKey)

			//If error, continue to the next read of the tcp tunnel
			if err != nil {
				fmt.Printf("Error opening file for reading: %v\n", err)
				continue
			}

			//Package the file in a message struct
			responseMsg := message{
				Action:   "RES_FILE",
				Filename: msg.Filename,
				Payload:  fileBytes,
			}

			//marshal; encrypt; and send encrypted message
			err = sendMessage(conn, responseMsg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending message: %v\n", err)
				continue
			}

			//Prompt user of success
			fmt.Printf("File %s has been sent to peer!\n", msg.Filename)

		//Handle the peer responding with their file list
		case "RES_LIST":

			//Header
			fmt.Printf("\n--- %s Available Files ---\n", peerName)

			//Prompt the user if the file list is empty
			if len(msg.FileList) == 0 {
				fmt.Println("- (Peer has shared no files or has none)")

			} else {

				//ADD A OPEN FILE WITH WRITE TO PEER LIST

				//Iterate through each filename in the list; print to user
				for _, filename := range msg.FileList {
					fmt.Println("-" + filename)
					//WRITE EACH FILENAME TO THE OPEN FILE
				}
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

				//Prompt the user the request has been approved
				fmt.Printf("Request for file '%s' has been approved! Downloading...\n", msg.Filename)
				//Begin download
				downloadAndSecure(msg.Filename, msg.Payload, storageKey)
			}

		//Handle the peer sending a file without it being requested
		case "SEND_FILE":

			//Get consent from the user
			fmt.Printf("[CONSENT REQUIRED] Peer %s has sent you file '%s'. Approve download? (Y/n): ", peerName, msg.Filename)

			//If the user denies it, continue to next tcp read
			if !getConsent() {
				fmt.Println("Download denied.")
				continue
			}

			//Otherwise, download file
			fmt.Println("Accepting file...")
			downloadAndSecure(msg.Filename, msg.Payload, storageKey)

		case "KEY_MIGRATION":
			fmt.Printf("\n[!] CRITICAL: Peer '%s' has migrated their key. Repairing contact...\n", peerName)
			newKey := msg.Payload
			oldFilename := fmt.Sprintf("peer_%s.pem", peerID)
			oldFilepath := filepath.Join("contacts", oldFilename)

			err := os.Remove(oldFilepath)
			if err != nil && !os.IsNotExist(err) {
				fmt.Printf("Failed to delete compromised contact %s: %v", oldFilename, err)
				continue
			}
			fmt.Printf("Deleted compromised contact: %s\n", oldFilename)

			_, err = saveContact(newKey)
			if err != nil {
				fmt.Printf("Failed to store new key: %v\n", err)
			}

		}

	}
}

func encrypt(plaintext []byte, sessionKey []byte, action string) ([]byte, error) {

	if action == "SEND_FILE" || action == "RES_FILE" {
		privKey, pubKey, err := loadIdentity("identity_priv.pem", "identity_pub.pem")
		if err != nil {
			return nil, fmt.Errorf("Critical error loading keys: %v\n", err)
		}

		//Create a digitial signature for the file
		hash := sha256.Sum256(plaintext)

		signature := ed25519.Sign(privKey, hash[:])

		fingerprint := pubKey[:12]

		plaintext = append(plaintext, fingerprint...)
		plaintext = append(plaintext, signature...)
	}

	//Create ciphertext

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

func decrypt(ciphertext []byte, sessionKey []byte) ([]byte, error) {

	//fingerprint := peerIdentity[:12]
	//fingerprintHex := hex.EncodeToString(fingerprint)

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("Ciphertext is too short")
	}

	nonce, realCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, realCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed; possible tampering: %v", err)
	}

	return plaintext, nil
}

func getFilesList(fileDir string) ([]string, error) {
	entries, err := os.ReadDir(fileDir)
	if err != nil {
		return nil, fmt.Errorf("Error fetching files: %v", err)
	}

	var files []string

	for _, e := range entries {
		files = append(files, e.Name())
	}

	return files, nil
}

func sendMessage(conn net.Conn, msg message, sessionKey []byte) error {

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(data, sessionKey, msg.Action)
	if err != nil {
		return err
	}

	payloadSize := uint32(len(ciphertext))
	prefixBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(prefixBuf, payloadSize)

	conn.Write(prefixBuf)
	conn.Write(ciphertext)

	return nil
}

func decodeMessage(conn net.Conn, sessionKey []byte) (message, error) {

	var msg message
	var emptyMsg message

	sizeBuf := make([]byte, 4)

	if _, err := io.ReadFull(conn, sizeBuf); err != nil {
		return msg, nil
	}

	msgSize := binary.BigEndian.Uint32(sizeBuf)

	ciphertext := make([]byte, msgSize)
	if _, err := io.ReadFull(conn, ciphertext); err != nil {
		return msg, fmt.Errorf("Failed to read payload: %v", err)
	}

	plaintext, err := decrypt(ciphertext, sessionKey)
	if err != nil {
		return msg, err
	}

	plaintext = bytes.Trim(plaintext, "\x00")

	if err := json.Unmarshal(plaintext, &msg); err != nil {
		return msg, fmt.Errorf("Failed to encode plaintext to message format: %v", err)
	}

	if msg.Action == "RES_FILE" || msg.Action == "SEND_FILE" {
		err = verifyData(ciphertext)
		if err != nil {
			return emptyMsg, err
		}
	}

	return msg, nil
}

func loadPublicKey(fingerprintHex string) (ed25519.PublicKey, error) {

	filename := fmt.Sprintf("peer_%s.pem", fingerprintHex)
	fullpath := filepath.Join("contacts", filename)

	fileBytes, err := os.ReadFile(fullpath)
	if err != nil {
		return nil, fmt.Errorf("Unrecognized peer: %v", err)
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		return nil, fmt.Errorf("Failed to parse PEM blocks in file '%s'", filename)
	}

	if block.Type != "Peer Public Key" {
		return nil, fmt.Errorf("invalid PEM type: Expected 'Peer Public Key', got %s", block.Type)
	}

	return ed25519.PublicKey(block.Bytes), nil
}

func verifyData(data []byte) error {
	if len(data) < 76 {
		return fmt.Errorf("File is too small to contain a signature")
	}

	splitIdx := len(data) - 76
	ciphertext := data[:splitIdx]
	tail := data[splitIdx:]

	fingerprint := tail[:12]
	signature := tail[12:]

	hash := sha256.Sum256(ciphertext)

	fingerprintHex := hex.EncodeToString(fingerprint)
	pubKey, err := loadPublicKey(fingerprintHex)
	if err != nil {
		return fmt.Errorf("Unknown creator fingerprint: %s\n", fingerprintHex)
	}

	isValid := ed25519.Verify(pubKey, hash[:], signature)
	if !isValid {
		return fmt.Errorf("FILE VERIFICATION FAILED: File has been tampered with.")
	}

	return nil
}
