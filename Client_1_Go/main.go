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

// Helper function to grab clients IP address
func getLocalIP() []net.IP {

	//Create a dummy connection
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatalf("Error finding local IP...: %v", err)
		return nil
	}

	//Close connection on function return
	defer conn.Close()

	//Fetch the clients local IP from the connection
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	//Return as a slice type net.IP
	return []net.IP{localAddr.IP}
}

// Main function; Handles UI
func main() {

	//Create client node
	myNode := Node{
		nodeID:      "Go_Client",
		serviceType: "_cisc468p2p._tcp",
		domain:      "local.",
		IP:          getLocalIP(),
		port:        5000,
	}

	//Check for client's identity key pair
	privPath := "identity_priv.pem"
	pubPath := "identity_pub.pem"

	//If the files do not exist, create id key pair
	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		fmt.Println("No identity found. Generating new keys...")

		if err := createIdentity(privPath, pubPath); err != nil {
			log.Fatalf("Critical error generating keys: %v", err)
		}
	}

	//Load keypair
	privKey, pubKey, err := loadIdentity(privPath, pubPath)
	if err != nil {
		log.Fatalf("Critical error loading keys: %v\n", err)
	}

	//Begin broadcasting in the background
	server, err := myNode.broadcast()
	if err != nil {
		log.Fatalf("Error broadcasting node A: %v\n", err)
	}

	//Defer broadcasting shutdown until end of program
	defer server.Shutdown()

	//Create a manager for peer connections and sessionkeys
	peerManager := CreatePeerManager()

	//Fetch the key for client'slocal storage
	storageKey, err := generateStorageKey()
	if err != nil {
		log.Fatalf("%v", err)
	}

	//Initialize list of peers, as well as list of peerIDs
	var peerList []Node
	var peerIDs []string

	//Create scanner to read stdin
	scanner := bufio.NewScanner(os.Stdin)

	//Print welcome messages
	fmt.Println("Welcome to the GO P2P client!")
	fmt.Println("Available commands:\n\t- 'peers' to see peers added\n\t- 'initiate <peerID>' to interact with a peer")
	fmt.Println("\t- 'discover' to connect to peers\n\t- 'migrate' to issue a new key if old one is compromised")
	fmt.Println("\t- 'import' move files into secure storage\n\t- 'export' to move & decrypt a securely stored file")
	fmt.Println("\t- 'exit' or 'quit' to exit program.")

	for {
		//Separate input into arguments
		fmt.Printf("\n<home --- cmd> ")
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())
		args := strings.Split(input, " ")

		//The first arg is the switch word
		command := args[0]

		switch command {

		//Handles client wanting to connect with local peers
		case "discover":

			//Create a timeout for the discover method
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			//Fetch the peerlist from the mDNS discover method
			peerList, err = myNode.discover(ctx)
			if err != nil {
				fmt.Printf("Discovery Error: %v", err)
				continue
			}

			//Prompt user of search results
			fmt.Printf("Search complete! Found %d peers.\n", len(peerList))

			//Initiate a new DHKE with each peer in the peerlist
			for _, peer := range peerList {
				conn, sessionKey, fingerprint, err := startDHKE(&myNode, &peer, privKey, pubKey)

				//Handle if the user did not TOFU with a new peer
				if err == fmt.Errorf("The peer was not trusted on first use. Aborting...") {
					continue
				}
				//Handle any other error
				if err != nil {
					log.Fatalf("%v", err)
				}
				//Begin a goroutine to handle incoming traffic in the background
				go handleInbound(conn, sessionKey, storageKey, fingerprint, peer.nodeID)
				//Save peer's info (connection, sessionkey) & their peerID
				peerManager.AddPeer(peer.nodeID, conn, sessionKey, fingerprint)
				peerIDs = append(peerIDs, peer.nodeID)
			}

		//Handles if the user's key has been compromised
		case "migrate":

			//Prompt user of action
			fmt.Println("Key has been compromised! Generating new identity and notifying peers...")
			//Begin generating new identity
			if err = createIdentity(privPath, pubPath); err != nil {
				log.Fatalf("Critical error generating keys: %v", err)
			}

			//Load the new public key
			_, newPubKey, err := loadIdentity(privPath, pubPath)
			if err != nil {
				log.Fatalf("Critical error loading keys: %v\n", err)
			}

			//Iterate through each peer
			for _, peerID := range peerIDs {

				//Fetch their info
				currConn := peerManager.connections[peerID]
				currSessionKey := peerManager.sessionKeys[peerID]

				//Send a KEY_MIGRATION message to notify them of the new key
				migrationMsg := message{
					Action:  "KEY_MIGRATION",
					Payload: newPubKey,
				}
				sendMessage(currConn, migrationMsg, currSessionKey)

				//Delete the connection to peer as it has been compromised
				peerManager.RemovePeer(peerID)
				peerIDX := slices.Index(peerIDs, peerID)
				peerIDs = slices.Delete(peerIDs, peerIDX, peerIDX+1)

				//Close the connection
				currConn.Close()

			}

		//Handle user wanting to interact with a given peer
		case "initiate":

			//Ensure a peerID has been passed
			if len(args) < 2 {
				fmt.Println("Usage: initiate <peerID>")
				continue
			}
			peerID := args[1]

			//Find the peer's info in the peer manager
			conn, sessionKey, _, exists := peerManager.FetchPeer(peerID)
			if !exists {
				fmt.Printf("Peer '%s' does not exist. Sorry...\n", peerID)
				continue
			}
			//Begin the outbound UI for that peer
			handleOutbound(conn, sessionKey, storageKey, peerID)

		//Handles the user requesting their current contact book
		case "peers":
			fmt.Println("Current Contact Book")
			for _, peer := range peerIDs {
				fmt.Println("-", peer)
			}

		//Handles user requesting to securely store their file in the system
		case "import":
			fmt.Println("Importing files to secure storage.")
			//Securely store every file in the 'ImportFiles' folder
			importFiles(storageKey)

		//Handles user requesting to export a file from their secure storage
		case "export":
			//Ensure a filename was given
			if len(args) < 2 {
				fmt.Println("Usage: export <filename>")
			}
			filename := args[1]

			//Export given file
			fmt.Println("Exporting files to secure storage.")
			exportFile(filename, storageKey)

		//Handles user exiting the program
		case "exit", "quit":

			//Close all current connections
			fmt.Println("Logging off...")
			for _, conn := range peerManager.connections {
				conn.Close()
			}
			//Quit program
			return

		//Reprints list of available commands
		default:
			fmt.Println("Available commands:\n\t- 'peers' to see peers added\n\t- 'initiate <peerID>' to interact with a peer")
			fmt.Println("\t- 'discover' to connect to peers\n\t- 'migrate' to issue a new key if old one is compromised")
			fmt.Println("\t- 'import' move files into secure storage\n\t- 'export' to move & decrypt a securely stored file")
			fmt.Println("\t- 'exit' or 'quit' to exit program.")
		}
	}
}
