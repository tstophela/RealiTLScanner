package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ScanResult holds the result of a TLS scan for a single host.
type ScanResult struct {
	IP          string
	Port        string
	ServerName  string
	TLSVersion  string
	CipherSuite string
	Cert        *CertInfo
	RealitySupport bool
	Latency     time.Duration
	Error       string
}

// CertInfo contains relevant certificate information extracted during scanning.
type CertInfo struct {
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	SANs        []string
}

// Scanner performs TLS handshake scanning against a target host.
type Scanner struct {
	Timeout    time.Duration
	ServerName string
}

// NewScanner creates a new Scanner with the given timeout and optional SNI server name.
func NewScanner(timeout time.Duration, serverName string) *Scanner {
	return &Scanner{
		Timeout:    timeout,
		ServerName: serverName,
	}
}

// Scan connects to the given address and performs a TLS handshake, returning scan results.
func (s *Scanner) Scan(ip, port string) *ScanResult {
	result := &ScanResult{
		IP:   ip,
		Port: port,
	}

	addr := net.JoinHostPort(ip, port)

	dialer := &net.Dialer{
		Timeout: s.Timeout,
	}

	serverName := s.ServerName
	if serverName == "" {
		serverName = ip
	}

	result.ServerName = serverName

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // We want to scan even self-signed certs
		MinVersion:         tls.VersionTLS12,
	}

	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	result.Latency = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()

	result.TLSVersion = tlsVersionName(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Check for REALITY indicator: TLS 1.3 with specific cipher suite
	result.RealitySupport = state.Version == tls.VersionTLS13

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Cert = &CertInfo{
			Subject:   cert.Subject.CommonName,
			Issuer:    cert.Issuer.CommonName,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			SANs:      cert.DNSNames,
		}
	}

	return result
}

// tlsVersionName returns a human-readable name for a TLS version constant.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", version)
	}
}
