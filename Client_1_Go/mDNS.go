package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/grandcat/zeroconf"
)

// Node structure
type Node struct {
	nodeID      string
	serviceType string
	domain      string
	IP          []net.IP
	port        int
}

// Function to broadcast the client for peer discovery
func (n *Node) broadcast() (*zeroconf.Server, error) {

	//Create the service
	server, err := zeroconf.Register(n.nodeID, n.serviceType, n.domain, n.port, nil, nil)

	//Handle error if mDNS does not start
	if err != nil {
		log.Fatalf("Failed to start mDNS: %v", err)
	}

	//Defer shutdown until after broadcast window
	fmt.Printf("Node '%s' is now broadcasting locally...\n", n.nodeID)

	//Return the server object
	return server, nil

}

// Function for peer discovery
func (n *Node) discover(ctx context.Context) ([]Node, error) {

	//Create the resolver; needed for peer discovery
	resolver, err := zeroconf.NewResolver(nil)

	//Handle error if resolver failed
	if err != nil {
		log.Fatalf("Failed to initialize resolver: %v", err)
	}

	//Create a channel for peer discoveries: Entries
	entries := make(chan *zeroconf.ServiceEntry)
	//Create the return list of peers found
	peerList := make([]Node, 0, 10)

	//Search for peers on the same service and domain
	err = resolver.Browse(ctx, n.serviceType, n.domain, entries)
	if err != nil {
		return nil, fmt.Errorf("Failed to browse: %v", err)
	}

	//Iterate through each peer found and append them to the return list
	for peer := range entries {
		if peer.Instance != n.nodeID {
			fmt.Printf("Peer found! Name: %s, IP: %v, Port: %d\n", peer.Instance, peer.AddrIPv4, peer.Port)
			//Create a node for the current peer
			tempNode := Node{peer.Instance, n.serviceType, n.domain, peer.AddrIPv4, peer.Port}
			//Add peer's node to our return list
			peerList = append(peerList, tempNode)
		}
	}

	//Return list of found peers
	return peerList, nil
}
