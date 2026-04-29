package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ScanResult holds the result of a single TLS scan for an IP address.
type ScanResult struct {
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	Domain      string    `json:"domain,omitempty"`
	TLSVersion  string    `json:"tls_version,omitempty"`
	CipherSuite string    `json:"cipher_suite,omitempty"`
	IsReality   bool      `json:"is_reality"`
	Country     string    `json:"country,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	Latency     int64     `json:"latency_ms,omitempty"`
	ScannedAt   time.Time `json:"scanned_at"`
	Error       string    `json:"error,omitempty"`
}

// ResultWriter manages writing scan results to output destinations.
type ResultWriter struct {
	mu       sync.Mutex
	file     *os.File
	encoder  *json.Encoder
	count    int
	filePath string
}

// NewResultWriter creates a new ResultWriter that writes JSON lines to the given file path.
// If filePath is empty, results are written to stdout.
func NewResultWriter(filePath string) (*ResultWriter, error) {
	rw := &ResultWriter{
		filePath: filePath,
	}

	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open output file %s: %w", filePath, err)
		}
		rw.file = f
		rw.encoder = json.NewEncoder(f)
	} else {
		rw.encoder = json.NewEncoder(os.Stdout)
	}

	return rw, nil
}

// Write serializes a ScanResult as a JSON line and writes it to the output.
func (rw *ResultWriter) Write(result *ScanResult) error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if err := rw.encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to write result for IP %s: %w", result.IP, err)
	}
	rw.count++
	return nil
}

// Count returns the total number of results written so far.
func (rw *ResultWriter) Count() int {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.count
}

// Close flushes and closes the underlying file, if any.
func (rw *ResultWriter) Close() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.file != nil {
		if err := rw.file.Close(); err != nil {
			return fmt.Errorf("failed to close output file: %w", err)
		}
		rw.file = nil
	}
	return nil
}

// Summary prints a brief summary of the scan session to stderr.
func (rw *ResultWriter) Summary(total int, duration time.Duration) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	fmt.Fprintf(os.Stderr, "\n--- Scan Summary ---\n")
	fmt.Fprintf(os.Stderr, "Total IPs scanned : %d\n", total)
	fmt.Fprintf(os.Stderr, "Reality hits found: %d\n", rw.count)
	fmt.Fprintf(os.Stderr, "Duration          : %s\n", duration.Round(time.Millisecond))
	if rw.filePath != "" {
		fmt.Fprintf(os.Stderr, "Results written to: %s\n", rw.filePath)
	}
}
