package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/hkdf"
)

// Function used to compare IPs; Used to determine roles for TCP connection
func compareIPs(ipA, ipB net.IP) int {

	//Convert both to a 16-byte representation
	normA := ipA.To16()
	normB := ipB.To16()

	//Return result of comparison;
	//-1 if normA > normB, 1 if A<B, 0 if A==B
	return bytes.Compare(normA, normB)
}

// Create an identity key
func createIdentity(privPath string, pubPath string) error {

	//Create keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	//Handle key generation error
	if err != nil {
		return fmt.Errorf("Error creating keys: %w", err)
	}

	//Process the number of bytes in both
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("Error processing private key: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("Error processing public key: %w", err)
	}

	//Create PEM block for both; used to securely store the keys
	privPEM := &pem.Block{
		Type:  "Private Key",
		Bytes: privBytes,
	}
	pubPEM := &pem.Block{
		Type:  "Public Key",
		Bytes: pubBytes,
	}

	//Use 0600 as permissions: Read/Write for Owner only
	err = os.WriteFile(privPath, pem.EncodeToMemory(privPEM), 0600)
	if err != nil {
		return fmt.Errorf("Error saving private key: %w", err)
	}

	//Use 0644 as permissions: Write for Owner, Read for everyone else
	err = os.WriteFile(pubPath, pem.EncodeToMemory(pubPEM), 0644)
	if err != nil {
		return fmt.Errorf("Error saving private key: %w", err)
	}

	//Prompt user keys have been generated
	fmt.Println("Successfully created and saved identity keys")
	return nil
}

// Function to fetch client's private and public key; Used for creating session key with peer
func loadIdentity(privPath string, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {

	//Load both private and public PEM blocks
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	//Decode PEM blocks into private and public key blocks
	privBlock, _ := pem.Decode(privData)
	if privBlock == nil || privBlock.Type != "Private Key" {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	pubBlock, _ := pem.Decode(pubData)
	if pubBlock == nil || pubBlock.Type != "Public Key" {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	//Parse the PKCS#8 data block back into a crypto object
	parsedPrivKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	parsedPubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	//Convert data blocks back into ed25519.PrivateKey, and ed25519.PublicKey type respectively
	privateKey, ok := parsedPrivKey.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not of type Ed25519")
	}
	publicKey, ok := parsedPubKey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("public key is not of type Ed25519")
	}

	//Return keypair
	return privateKey, publicKey, nil
}

// Function called to start a DHKE with a given peer
func startDHKE(host *Node, peer *Node, privIdentity ed25519.PrivateKey, pubIdentity ed25519.PublicKey) (net.Conn, []byte, string, error) {

	//Initialize variables
	var conn net.Conn
	var peerIdentityKey []byte
	var peerEphemeralKey []byte

	//Create the initial curve and private key; Handle errors
	curve := ecdh.X25519()
	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	//Create public key using private key
	ephemeralPub := ephemeralPriv.PublicKey().Bytes()

	//Create signature based on private key and public ephermeral
	signature := ed25519.Sign(privIdentity, ephemeralPub)

	//Create the user payload to send to peer; public key + ephemeral public key + signature
	payload := make([]byte, 0, 128)
	payload = append(payload, []byte(pubIdentity)...) //32-bytes
	payload = append(payload, ephemeralPub...)        //32-bytes
	payload = append(payload, signature...)           //64-bytes

	//Grab IP's of peer and host
	ipA := host.IP[0]
	ipB := peer.IP[0]

	//If the host's IP is higher than the peer's, host shall act as server(listener)
	if compareIPs(ipA, ipB) > 0 {

		//Listen on host's specified port
		port := fmt.Sprintf(":%d", host.port)
		listener, err := net.Listen("tcp", port)
		if err != nil {
			return nil, nil, "", fmt.Errorf("Error listening on tcp: %v", err)
		}

		//Accept the connection; handle errors
		conn, err = listener.Accept()
		if err != nil {
			return nil, nil, "", fmt.Errorf("Error accepting handshake: %v", err)

		}

		//Listen for peer's Public Identity and EphemeralKey
		peerIdentityKey, peerEphemeralKey, _, err = readDHKE(conn)
		if err != nil {
			return nil, nil, "", err
		}

		//After listening, send client's payload containing:
		//Client public ID key, ephemeralKey, signature
		err = writeDHKE(conn, payload)
		if err != nil {
			return nil, nil, "", err
		}

		//Otherwise, host is the 'dialler'
	} else {

		//Dial the peer and establish a TCP tunnel
		peerIP, peerPort := peer.IP[0].String(), strconv.Itoa(peer.port)
		address := net.JoinHostPort(peerIP, peerPort)
		conn, err = net.Dial("tcp", address)

		//Send payload first
		err = writeDHKE(conn, payload)
		if err != nil {
			return nil, nil, "", err
		}

		//Then listen for Peer's Information
		peerIdentityKey, peerEphemeralKey, _, err = readDHKE(conn)
		if err != nil {
			return nil, nil, "", err
		}

	}

	//Check if connecting peer is known or a new user
	ok := compareHashes(peerIdentityKey, "contacts")
	if ok {
		fmt.Println("Peer is already a contact! Connecting now...")
		//If new, ask if the client would like to trust on first use
	} else {
		fmt.Print("This is a new peer, would you like to Trust on First Use (y/n): ")

		//If the client rejects TOFU, abort
		if !getConsent() {
			return nil, nil, "", fmt.Errorf("The peer was not trusted on first use. Aborting...")
		}
	}

	//Use the peer's ephemeral key to create their public key
	peerPublicKey, err := curve.NewPublicKey(peerEphemeralKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("Invalid ephemeral key from peer: %w", err)
	}

	//Raise our ephemeral private key to the peer's ephemeral public key
	sharedSecret, err := ephemeralPriv.ECDH(peerPublicKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("Failed to compute shared secret: %w", err)
	}

	//Create the session key using the created shared secret
	sessionKey, err := DeriveSessionKey(sharedSecret)

	//Save the peer as a contact using their public id key
	fingerprintHex, err := saveContact(peerIdentityKey)
	if err != nil {
		fmt.Printf("Error saving contact: %v", err)
	}

	//Prompt user connection has been established!
	fmt.Println("Connection established!")
	//Return the connection, sessionKey, and fingerprintHex for later use
	return conn, sessionKey, fingerprintHex, err
}

// Function to read the TCP tunnel; used to obtain peer's keys used to create the shared secret
func readDHKE(conn net.Conn) ([]byte, []byte, []byte, error) {

	//Initialize the payload
	peerPayload := make([]byte, 128)
	//Read the TCP tunnel; Will hang until peer has sent a payload
	_, err := io.ReadFull(conn, peerPayload)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Error reading peer's payload: %v", err)
	}

	//Create peer's keys + signature from their payload
	peerIdentityKey := peerPayload[0:32]
	peerEphemeralKey := peerPayload[32:64]
	peerSignature := peerPayload[64:128]

	//Verify that the signature is valid for the peer's public key
	ok := ed25519.Verify(peerIdentityKey, peerEphemeralKey, peerSignature)
	if !ok {
		return nil, nil, nil, fmt.Errorf("PEER SIGNATURE IS INVALID.")
	}

	//Return peer's keys + signature
	return peerIdentityKey, peerEphemeralKey, peerSignature, nil
}

// Function to send payload to peer; used to create shared secret on their end
func writeDHKE(conn net.Conn, payload []byte) error {

	//Send payload to the peer
	_, err := conn.Write(payload)
	if err != nil {
		return fmt.Errorf("Failed to send handshake: %w", err)
	}

	//Return cleanly
	return nil
}

// Function to derive the session key using the shared secret
func DeriveSessionKey(sharedSecret []byte) ([]byte, error) {

	//Create new hash
	hash := sha256.New

	//Standardized info between all clients
	info := []byte("P2P File Transfer")

	//Create a new hkdf using the hash and shared secret
	kdf := hkdf.New(hash, sharedSecret, nil, info)

	//Create the session key and handle errors
	sessionKey := make([]byte, 32)
	_, err := io.ReadFull(kdf, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to derive session key: %v", err)
	}

	//Return sessionKey
	return sessionKey, nil
}

// Function used to save a peer as a contact; Prevents a TOFU message on every subsequent connection
func saveContact(peerIdentity []byte) (string, error) {

	//Create short hash digest of the peer's public identity
	hash := sha256.Sum256(peerIdentity)
	fingerprintHex := hex.EncodeToString(hash[:])[:12]

	//Create filename using hash digest
	filename := fmt.Sprintf("peer_%s.pem", fingerprintHex)
	fullpath := filepath.Join("contacts", filename)

	//Ensure the contacts folder exists; Owner can r/w/x while others can only r/x
	err := os.MkdirAll("contacts", 0755)
	if err != nil {
		return "", fmt.Errorf("Error creating directory: %v", err)
	}

	//Create the pem block for the peer's identity
	pubPEM := &pem.Block{
		Type:  "Peer Public Key",
		Bytes: peerIdentity,
	}

	//Use 0600 as permissions: Owner can r/w/x while others can only r/x
	err = os.WriteFile(fullpath, pem.EncodeToMemory(pubPEM), 0600)
	if err != nil {
		return "", fmt.Errorf("Error saving private key: %w", err)
	}

	//Prompt user new peer has been saved
	fmt.Printf("Peer has been saved!\n")

	//Return their fingerprintHex if needed
	return fingerprintHex, nil
}

// Function used to check if a peer is already a contact
func compareHashes(id []byte, contactDir string) bool {

	//Create a hash & fingerprint of the id
	hash := sha256.Sum256(id)
	fingerprintHex := hex.EncodeToString(hash[:])[:12]

	//Create its theoretical file path
	filename := fmt.Sprintf("peer_%s.pem", fingerprintHex)
	fullpath := filepath.Join(contactDir, filename)

	//Check if the peer is in the contact book
	_, err := os.Stat(fullpath)
	if err != nil {
		//Return false if they are not
		if os.IsNotExist(err) {
			return false
		}

	}

	//True if they are
	return true
}
