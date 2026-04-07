package main

import (
	"net"
	"sync"
)

type PeerManager struct {
	mu           sync.RWMutex
	connections  map[string]net.Conn
	sessionKeys  map[string][]byte
	fingerprints map[string]string
}

func (pm *PeerManager) AddPeer(peerID string, conn net.Conn, sessionKey []byte, fingerprint string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.connections[peerID] = conn
	pm.sessionKeys[peerID] = sessionKey
	pm.fingerprints[peerID] = fingerprint
}

func (pm *PeerManager) FetchPeer(peerID string) (net.Conn, []byte, string, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	conn, exists := pm.connections[peerID]
	sessionKey := pm.sessionKeys[peerID]
	fingerprintHex := pm.fingerprints[peerID]

	return conn, sessionKey, fingerprintHex, exists
}

func CreatePeerManager() *PeerManager {
	return &PeerManager{
		connections:  make(map[string]net.Conn),
		sessionKeys:  make(map[string][]byte),
		fingerprints: make(map[string]string),
	}
}
