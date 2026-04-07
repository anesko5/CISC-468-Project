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

func compareIPs(ipA, ipB net.IP) int {

	normA := ipA.To16()
	normB := ipB.To16()

	fmt.Println("Here")

	return bytes.Compare(normA, normB)
}

func createIdentity(privPath string, pubPath string) error {

	//Create keypair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	//Handle key generation error
	if err != nil {
		return fmt.Errorf("Error creating keys: %w", err)
	}

	//Save both keys securely

	//Process the number of bytes in both
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("Error processing private key: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("Error processing public key: %w", err)
	}

	//Create PEM block; will be the format the keys are stored in
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

	fmt.Println("Successfully created and saved identity keys")
	return nil
}

func loadIdentity(privPath string, pubPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// 1. Decode the PEM block
	privBlock, _ := pem.Decode(privData)
	if privBlock == nil || privBlock.Type != "Private Key" {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// 2. Parse the PKCS#8 data back into a Go crypto object
	parsedPrivKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// 3. Type assert it specifically to an ed25519.PrivateKey
	privateKey, ok := parsedPrivKey.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not of type Ed25519")
	}

	// --- LOAD PUBLIC KEY ---
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	pubBlock, _ := pem.Decode(pubData)
	if pubBlock == nil || pubBlock.Type != "Public Key" {
		return nil, nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	parsedPubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := parsedPubKey.(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("public key is not of type Ed25519")
	}

	fmt.Println("Finished loading keys!")
	return privateKey, publicKey, nil
}

func startDHKE(host *Node, peer *Node, privIdentity ed25519.PrivateKey, pubIdentity ed25519.PublicKey) (net.Conn, []byte, string, error) {

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

	ipA := host.IP[0]
	ipB := peer.IP[0]

	fmt.Println(ipA, ipB)

	//If the host's IP is higher than the peer's, host shall act as server(listener)
	if compareIPs(ipA, ipB) > 0 {

		//Listen on host's specified port
		port := fmt.Sprintf(":%d", host.port)
		listener, err := net.Listen("tcp", port)
		if err != nil {
			return nil, nil, "", fmt.Errorf("Error listening on tcp: %v", err)
		}

		conn, err = listener.Accept()
		if err != nil {
			return nil, nil, "", fmt.Errorf("Error accepting handshake: %v", err)

		}

		//Listen for DHKE request
		peerIdentityKey, peerEphemeralKey, _, err = readDHKE(conn)
		if err != nil {
			return nil, nil, "", err
		}

		err = writeDHKE(conn, payload)
		if err != nil {
			return nil, nil, "", err
		}

	} else {

		//Dial the peer and establish a TCP tunnel
		peerIP, peerPort := peer.IP[0].String(), strconv.Itoa(peer.port)

		address := net.JoinHostPort(peerIP, peerPort)
		conn, err = net.Dial("tcp", address)

		err = writeDHKE(conn, payload)
		if err != nil {
			return nil, nil, "", err
		}

		//Listen for DHKE request
		peerIdentityKey, peerEphemeralKey, _, err = readDHKE(conn)
		if err != nil {
			return nil, nil, "", err
		}

	}

	ok := compareHashes(peerIdentityKey, "contacts")
	if ok {
		fmt.Println("Peer is already a contact! Connecting now...")
	} else {
		fmt.Print("This is a new peer, would you like to Trust on First Use (y/n): ")

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

	sessionKey, err := DeriveSessionKey(sharedSecret)
	fingerprintHex, err := saveContact(peerIdentityKey)
	if err != nil {
		fmt.Printf("Error saving contact: %v", err)
	}

	//Return the shared secret
	//Return the connection so the main program can determine shutdown of the connection
	fmt.Println("Connection established!")
	return conn, sessionKey, fingerprintHex, err
}

func readDHKE(conn net.Conn) ([]byte, []byte, []byte, error) {

	peerPayload := make([]byte, 128)
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

	return peerIdentityKey, peerEphemeralKey, peerSignature, nil
}

func writeDHKE(conn net.Conn, payload []byte) error {

	//Send payload to the peer
	_, err := conn.Write(payload)
	if err != nil {
		return fmt.Errorf("Failed to send handshake: %w", err)
	}

	return nil
}

func DeriveSessionKey(sharedSecret []byte) ([]byte, error) {
	hash := sha256.New

	info := []byte("P2P File Transfer")

	kdf := hkdf.New(hash, sharedSecret, nil, info)

	sessionKey := make([]byte, 32)
	_, err := io.ReadFull(kdf, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to derive session key: %v", err)
	}

	return sessionKey, nil
}

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

	fmt.Printf("Peer has been saved!\n")
	return fingerprintHex, nil
}

func compareHashes(id []byte, contactDir string) bool {

	hash := sha256.Sum256(id)
	fingerprintHex := hex.EncodeToString(hash[:])[:12]

	filename := fmt.Sprintf("peer_%s.pem", fingerprintHex)
	fullpath := filepath.Join(contactDir, filename)

	_, err := os.Stat(fullpath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		return false
	}

	return true
}
