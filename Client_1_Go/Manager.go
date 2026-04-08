package main

import (
	"net"
	"sync"
)

// Create a struct to store each peer's connection and sessionkey
type PeerManager struct {
	mu           sync.RWMutex
	connections  map[string]net.Conn
	sessionKeys  map[string][]byte
	fingerprints map[string]string
}

// Function to add a peer's info to the manager
func (pm *PeerManager) AddPeer(peerID string, conn net.Conn, sessionKey []byte, fingerprint string) {

	//Lock the peer manager; avoid race condition with reading/writing dicts
	pm.mu.Lock()
	//Unlock the peer manager after function execution
	defer pm.mu.Unlock()

	//Store peers connection, sessionKey, fingerprint
	pm.connections[peerID] = conn
	pm.sessionKeys[peerID] = sessionKey
	pm.fingerprints[peerID] = fingerprint
}

// Function to handle removing a peer from the manager
func (pm *PeerManager) RemovePeer(peerID string) {

	//Lock the peer manager; avoid race condition with reading/writing dicts
	pm.mu.Lock()
	//Unlock the peer manager after function execution
	defer pm.mu.Unlock()

	//Delete peer info
	delete(pm.connections, peerID)
	delete(pm.sessionKeys, peerID)
	delete(pm.fingerprints, peerID)
}

// Function to fetch a peers info given their peerID
func (pm *PeerManager) FetchPeer(peerID string) (net.Conn, []byte, string, bool) {

	//Create a read lock to avoid race conditions
	pm.mu.RLock()
	//Unlock the peer manager after function execution
	defer pm.mu.RUnlock()

	//Fetch their info & bool if it exists
	conn, exists := pm.connections[peerID]
	sessionKey := pm.sessionKeys[peerID]
	fingerprintHex := pm.fingerprints[peerID]

	//Return info
	return conn, sessionKey, fingerprintHex, exists
}

// Helper function to create a new peer manager instance
func CreatePeerManager() *PeerManager {
	return &PeerManager{
		connections:  make(map[string]net.Conn),
		sessionKeys:  make(map[string][]byte),
		fingerprints: make(map[string]string),
	}
}
