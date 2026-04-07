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

type message struct {
	Action   string   `json:"action"`
	Filename string   `json:"filename"`
	Payload  []byte   `json:"payload"`
	FileList []string `json:"filelist"`
}

var pendingDownloads sync.Map

var pendingUploads sync.Map

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

			signedData, err := signData(fileBytes)
			if err != nil {
				fmt.Printf("Error signing file: %v\n", err)
				continue
			}

			msg := message{
				Action:   "SEND_FILE",
				Filename: safePath,
				Payload:  signedData,
			}

			err = sendMessage(conn, msg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending file '%s': %v\n", msg.Filename, err)
				continue
			}

			fmt.Printf("File '%s' has been sent to peer for approval!\n", msg.Filename)

		case "accept":
			if len(args) < 2 {
				fmt.Printf("Usage: accept <filename>")
				continue
			}

			filename := args[1]

			payloadInterface, exists := pendingDownloads.Load(filename)
			if !exists {
				fmt.Printf("No pending download for '%s'.\n", filename)
			}

			payload := payloadInterface.([]byte)
			pendingDownloads.Delete(filename)

			_, err := verifyData(payload)
			if err != nil {
				fmt.Printf("\n[!] CRITICAL: %v\n", err)
				fmt.Println("Dropping tampered file.")
				continue
			}

			err = downloadAndSecure(filename, payload, storageKey)
			if err != nil {
				fmt.Printf("[!] Error downloading file '%s': %v\n", filename, err)
				continue
			}

			fmt.Printf("Successfully downloaded '%s' to FileStorage!\n", filename)

		case "reject":
			if len(args) < 2 {
				fmt.Println("Usage: reject <filename>")
				continue
			}

			filename := args[1]

			pendingDownloads.Delete(filename)
			fmt.Printf("File %s has been rejected.\n", filename)

		case "approve":
			if len(args) < 2 {
				fmt.Println("Usage: approve <filename>")
				continue
			}
			filename := args[1]

			_, exists := pendingUploads.Load(filename)
			if !exists {
				fmt.Printf("No pending request for file %s.\n", filename)
				continue
			}

			safePath := filepath.Clean(filename)
			fullpath := filepath.Join("FileStorage", safePath)

			if _, err := os.Stat(fullpath); err != nil {
				fmt.Printf("File '%s' does not exist. Notifying peer...\n", safePath)
				denialMsg := message{Action: "RES_FILE", Filename: filename, FileList: []string{"NOT_FOUND"}}
				sendMessage(conn, denialMsg, sessionKey)
				pendingUploads.Delete(filename)
				continue
			}

			fileBytes, err := loadSecureFile(safePath, storageKey)
			if err != nil {
				fmt.Printf("Error loading file '%s' from storage: %v", filename, err)
				pendingUploads.Delete(filename)
				continue
			}

			signedData, err := signData(fileBytes)
			if err != nil {
				fmt.Printf("Error signing file: %v\n", err)
				pendingUploads.Delete(filename)
				continue
			}

			responseMsg := message{
				Action:   "RES_FILE",
				Filename: filename,
				Payload:  signedData,
			}

			err = sendMessage(conn, responseMsg, sessionKey)
			if err != nil {
				fmt.Printf("Error sending message: %v", err)
				continue
			}

			fmt.Printf("File '%s' has been approved and is being sent to peer\n", filename)
			pendingUploads.Delete(filename)

		case "deny":
			if len(args) < 2 {
				fmt.Println("Usage: deny <filename>")
				continue
			}
			filename := args[1]

			_, exists := pendingUploads.Load(filename)
			if !exists {
				fmt.Printf("No pending file request for '%s'\n", filename)
				continue
			}

			denialMsg := message{
				Action:   "RES_FILE",
				Filename: filename,
				FileList: []string{"DENIED"},
			}
			sendMessage(conn, denialMsg, sessionKey)

			pendingUploads.Delete(filename)
			fmt.Printf("Rejected request for file '%s'\n", filename)

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

			//Clean the path; Do this to avoid directory traversal attacks
			fmt.Printf("\n\n[ALERT] Peer %s is requesting file '%s'.\n", peerName, msg.Filename)
			fmt.Printf("\tType 'approve %s' or 'deny %s' to respond.\n", msg.Filename, msg.Filename)
			fmt.Printf("\t<%s --- cmd> ", peerName)

			pendingUploads.Store(msg.Filename, true)

		//Handle the peer responding with their file list
		case "RES_LIST":

			//Header
			fmt.Printf("\n--- %s Available Files ---\n", peerName)

			//Prompt the user if the file list is empty
			if len(msg.FileList) == 0 {
				fmt.Println("- (Peer has shared no files or has none)")

			} else {
				filename := fmt.Sprintf("peer_%s.txt", peerID)
				fullpath := filepath.Join("peerLists", filename)

				file, err := os.Create(fullpath)
				if err != nil {
					fmt.Printf("Error creating peer's file list: %v\n", err)
				}

				//Iterate through each filename in the list; print to user
				for _, filename := range msg.FileList {
					fmt.Println("-" + filename)
					if file != nil {
						file.WriteString(filename + "\n")
					}
				}
				if file != nil {
					fmt.Printf("Peer's file list has been saved to '%s'\n", fullpath)
				}
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

			_, err := verifyData(msg.Payload)
			if err != nil {
				fmt.Printf("[!] CRITICAL: %v\n", err)
				fmt.Printf("[!] Dropping tampered file '%s'.\n", msg.Filename)
				continue
			}

			fmt.Printf("Request for file '%s' approved! Downloading...\n", msg.Filename)
			downloadAndSecure(msg.Filename, msg.Payload, storageKey)
			fmt.Printf("\t<%s --- cmd> ", peerName)

		//Handle the peer sending a file without it being requested
		case "SEND_FILE":

			fmt.Printf("\n\n[PEER ALERT] Peer %s has sent you file '%s'.\n", peerName, msg.Filename)
			fmt.Printf("\tType 'accept %s' or 'reject %s' to respond.\n", msg.Filename, msg.Filename)
			fmt.Printf("\t<%s --- cmd> ", peerName)

			pendingDownloads.Store(msg.Filename, msg.Payload)

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
			fmt.Printf("\t<%s --- cmd> ", peerName)

		}

	}
}

func encrypt(plaintext []byte, sessionKey []byte, action string) ([]byte, error) {

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
	err = json.Unmarshal(plaintext, &msg)
	if err != nil {
		return msg, fmt.Errorf("Failed to encode plaintext to message format: %v", err)
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

func signData(data []byte) ([]byte, error) {
	privKey, pubKey, err := loadIdentity("identity_priv.pem", "identity_pub.pem")
	if err != nil {
		return nil, fmt.Errorf("Critical error loading keys: %v", err)
	}

	hash := sha256.Sum256(data)
	signature := ed25519.Sign(privKey, hash[:])

	pubHash := sha256.Sum256(pubKey)
	fingerprintHex := hex.EncodeToString(pubHash[:])[:12]

	bundle := make([]byte, 0, len(data)+76)
	bundle = append(bundle, data...)
	bundle = append(bundle, []byte(fingerprintHex)...)
	bundle = append(bundle, signature...)

	return bundle, nil
}

func verifyData(data []byte) ([]byte, error) {
	if len(data) < 76 {
		return nil, fmt.Errorf("File is too small to contain a signature")
	}

	splitIdx := len(data) - 76
	plaintext := data[:splitIdx]
	tail := data[splitIdx:]

	fingerprintBytes := tail[:12]
	signature := tail[12:]

	fingerprintHex := string(fingerprintBytes)
	hash := sha256.Sum256(plaintext)

	pubKey, err := loadPublicKey(fingerprintHex)
	if err != nil {
		return nil, fmt.Errorf("Unknown signature '%s': %v", fingerprintHex, err)
	}

	isValid := ed25519.Verify(pubKey, hash[:], signature)
	if !isValid {
		return nil, fmt.Errorf("FILE VERIFICATION FAILED: File has been tampered with")
	}

	return plaintext, nil
}
