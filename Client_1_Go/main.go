package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"time"
)

func getLocalIP() []net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatalf("Error finding local IP...: %v", err)
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return []net.IP{localAddr.IP}
}

func main() {

	node := Node{
		nodeID:      "Go_Client",
		serviceType: "_cisc468p2p._tcp",
		domain:      "local.",
		IP:          getLocalIP(),
		port:        5000,
	}

	privPath := "identity_priv.pem"
	pubPath := "identity_pub.pem"
	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		fmt.Println("No identity found. Generating new keys...")

		if err := createIdentity(privPath, pubPath); err != nil {
			log.Fatalf("Critical error generating keys: %v", err)
		}
	}
	privKey, pubKey, err := loadIdentity(privPath, pubPath)
	if err != nil {
		log.Fatalf("Critical error loading keys: %v\n", err)
	}

	server, err := node.broadcast()
	if err != nil {
		log.Fatalf("Error broadcasting node A: %v\n", err)
	}

	defer server.Shutdown()

	peerManager := CreatePeerManager()
	storageKey, err := generateStorageKey()
	if err != nil {
		log.Fatalf("%v", err)
	}

	var peerList []Node
	var peerIDs []string

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Welcome to the GO P2P client!")

	fmt.Println("Available commands: 'peers', 'initiate <peerID>', 'discover'")

	for {
		fmt.Printf("What would you like to do?: ")
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		args := strings.Split(input, " ")
		command := args[0]

		switch command {

		case "discover":

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			peerList, err = node.discover(ctx)
			if err != nil {
				fmt.Printf("Discovery Error: %v", err)
				continue
			}

			fmt.Printf("Search complete! Found %d peers.\n", len(peerList))

			for _, peer := range peerList {
				conn, sessionKey, fingerprint, err := startDHKE(&node, &peer, privKey, pubKey)
				if err != nil {
					log.Fatalf("%v", err)
				}
				go handleInbound(conn, sessionKey, storageKey, fingerprint, peer.nodeID)
				peerManager.AddPeer(peer.nodeID, conn, sessionKey, fingerprint)
				peerIDs = append(peerIDs, peer.nodeID)
			}

		case "migrate":
			fmt.Println("Key has been compromised! Generating new identity and notifying peers...")
			if err = createIdentity(privPath, pubPath); err != nil {
				log.Fatalf("Critical error generating keys: %v", err)
			}

			_, newPubKey, err := loadIdentity(privPath, pubPath)
			if err != nil {
				log.Fatalf("Critical error loading keys: %v\n", err)
			}

			for _, peerID := range peerIDs {
				currConn := peerManager.connections[peerID]
				currSessionKey := peerManager.sessionKeys[peerID]

				migrationMsg := message{
					Action:  "KEY_MIGRATION",
					Payload: newPubKey,
				}

				sendMessage(currConn, migrationMsg, currSessionKey)

				delete(peerManager.connections, peerID)
				delete(peerManager.sessionKeys, peerID)
				peerIDX := slices.Index(peerIDs, peerID)
				peerIDs = slices.Delete(peerIDs, peerIDX, peerIDX+1)

				currConn.Close()

			}

		case "initiate":
			if len(args) < 2 {
				fmt.Println("Usage: initiate <peerID>")
				continue
			}

			peerID := args[1]

			conn, sessionKey, _, exists := peerManager.FetchPeer(peerID)
			if !exists {
				fmt.Printf("Peer '%s' does not exist. Sorry...\n", peerID)
				continue
			}
			handleOutbound(conn, sessionKey, storageKey)

		case "peers":
			fmt.Println("Current Contact Book")
			for _, peer := range peerIDs {
				fmt.Println("-", peer)
			}

		case "import":
			fmt.Println("Importing files to secure storage.")
			importFiles(storageKey)

		case "export":
			if len(args) < 2 {
				fmt.Println("Usage: export <filename>")
			}
			filename := args[1]

			fmt.Println("Exporting files to secure storage.")
			exportFile(filename, storageKey)

		case "exit", "quit":
			fmt.Println("Logging off...")
			for _, conn := range peerManager.connections {
				conn.Close()
			}
			return

		default:
			fmt.Println("Available commands: 'peers', 'initiate <peerID>', 'discover', 'import'")
		}
	}
}
