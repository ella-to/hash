// Package hash provides utilities for SHA256 hash generation and manipulation.
// It offers a custom Hash type with convenient string formatting, parsing,
// and various input sources including bytes, readers, and tee readers.
//
// The package standardizes hash representation with a "sha256-" prefix
// and provides consistent error handling and validation.
package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

const (
	// hashName defines the hash algorithm used throughout the package
	hashName = "sha256"

	// hashHeader is the prefix used in string representations of hashes
	hashHeader = hashName + "-"

	// StringSize is the total length of a hash in string format including the header
	// Format: "sha256-" (7 chars) + hex encoded hash (64 chars) = 71 chars total
	StringSize = 64 + len(hashHeader)

	// ByteSize is the size of a SHA256 hash in bytes (32 bytes = 256 bits)
	ByteSize = 32
)

// Hash is a custom type that wraps a byte slice representing a SHA256 hash value.
// It provides convenient methods for formatting, parsing, and marshaling/unmarshaling.
// The underlying byte slice should always be exactly 32 bytes (256 bits) for SHA256.
type Hash []byte

// String returns the full string representation of the hash with the "sha256-" prefix.
// The format is: "sha256-" followed by the lowercase hexadecimal representation.
// This method is safe for concurrent use.
//
// Example: "sha256-a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
func (h Hash) String() string {
	// Use a pre-allocated byte buffer to avoid multiple allocations
	buf := make([]byte, StringSize)

	// Copy the header directly
	copy(buf, hashHeader)

	// Encode hex directly into the buffer
	hex.Encode(buf[len(hashHeader):], h)

	return string(buf)
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// It parses a hash from its string representation back into a Hash value.
// The input must be in the format returned by String().
// Optimized to work directly on bytes without string conversion.
//
// This method enables automatic unmarshaling from JSON, YAML, and other text formats.
func (h *Hash) UnmarshalText(text []byte) error {
	rr, err := parseFromStringBytes(text)
	if err != nil {
		return fmt.Errorf("hash: failed to unmarshal text: %w", err)
	}

	*h = rr
	return nil
}

// parseFromStringBytes parses hash from byte representation of string format
// Optimized version that works directly on bytes
func parseFromStringBytes(text []byte) (Hash, error) {
	if len(text) != StringSize {
		return nil, fmt.Errorf("hash: invalid hash string length %d, expected %d", len(text), StringSize)
	}

	// Check prefix without string conversion
	headerBytes := []byte(hashHeader)
	for i, b := range headerBytes {
		if text[i] != b {
			return nil, fmt.Errorf("hash: invalid hash prefix")
		}
	}

	// Decode hex directly from bytes
	hexPart := text[len(hashHeader):]
	b := make([]byte, ByteSize)
	n, err := hex.Decode(b, hexPart)
	if err != nil {
		return nil, fmt.Errorf("hash: invalid hexadecimal encoding: %w", err)
	}

	if n != ByteSize {
		return nil, fmt.Errorf("hash: decoded hash size %d, expected %d", n, ByteSize)
	}

	return Hash(b), nil
}

// MarshalText implements the encoding.TextMarshaler interface.
// It returns the string representation of the hash as bytes.
// Optimized to avoid string allocation.
//
// This method enables automatic marshaling to JSON, YAML, and other text formats.
func (h Hash) MarshalText() ([]byte, error) {
	// Encode directly to bytes without intermediate string
	buf := make([]byte, StringSize)
	copy(buf, hashHeader)
	hex.Encode(buf[len(hashHeader):], h)
	return buf, nil
}

// Short returns the last 5 characters of the hash string representation.
// This is useful for displaying abbreviated hash values in logs or UI.
// Optimized to work directly on bytes without creating full string.
//
// Example: If hash is "sha256-a665a4...7a27ae3", this returns "27ae3"
func (h Hash) Short() string {
	if len(h) < 3 {
		return h.String() // Fallback for invalid hashes
	}

	// Take last 2.5 bytes (5 hex chars) and encode to hex directly
	lastBytes := h[len(h)-3:]
	buf := make([]byte, 6) // 3 bytes = 6 hex chars
	hex.Encode(buf, lastBytes)
	return string(buf[1:]) // Skip first char to get exactly 5 chars
}

// FromBytes computes the SHA256 hash of the provided byte slice.
// This is the most basic hash generation function and is safe for concurrent use.
// It accepts any byte slice, including nil or empty slices.
func FromBytes(content []byte) Hash {
	hasher := sha256.New()
	hasher.Write(content)
	return hasher.Sum(nil)
}

// FromBytesReuse computes the SHA256 hash using a pre-allocated output slice.
// This version allows reusing an existing 32-byte slice to avoid allocation.
// The output slice must be exactly 32 bytes or it will be reallocated.
//
// This is an optimization for hot paths where allocation overhead matters.
func FromBytesReuse(content []byte, output []byte) Hash {
	hasher := sha256.New()
	hasher.Write(content)

	// Reuse output slice if it's the right size
	if len(output) == ByteSize && cap(output) >= ByteSize {
		return hasher.Sum(output[:0])
	}

	return hasher.Sum(nil)
}

// FromReader computes the SHA256 hash by reading all data from the provided io.Reader.
// This function is useful for hashing data from files, network streams, or any io.Reader.
// The reader is consumed entirely during this operation.
//
// Returns an error if reading from the reader fails.
func FromReader(r io.Reader) (Hash, error) {
	hasher := sha256.New()

	// Get buffer from pool
	_, err := io.Copy(hasher, r)
	if err != nil {
		return nil, fmt.Errorf("hash: failed to read from reader: %w", err)
	}

	return hasher.Sum(nil), nil
}

// FromTeeReader creates a TeeReader that allows reading data while simultaneously
// computing its hash. This is more memory-efficient than reading all data into
// memory first when you need both the data and its hash.
//
// Returns:
// - io.Reader: A reader that provides the same data as the input reader
// - func() Hash: A function that returns the computed hash (call after reading is complete)
//
// The hash function should only be called after all data has been read from the returned reader.
func FromTeeReader(r io.Reader) (io.Reader, func() Hash) {
	hasher := sha256.New()
	return io.TeeReader(r, hasher), func() Hash {
		return hasher.Sum(nil)
	}
}

// TeeReader provides an alternative implementation of io.TeeReader specifically
// designed for hash computation. It reads from an underlying reader while
// simultaneously writing the data to a hash function.
//
// This struct is useful when you need more control over the reading process
// compared to the standard library's io.TeeReader.
type TeeReader struct {
	r      io.Reader // underlying reader to read data from
	hasher hash.Hash // hash function to write data to
}

// Read implements the io.Reader interface. It reads data from the underlying
// reader and simultaneously writes it to the hasher for hash computation.
//
// The method handles the case where n > 0 bytes are read, even if an error occurs.
// It returns io.EOF only when no bytes are read and the underlying reader returns EOF.
func (r *TeeReader) Read(b []byte) (int, error) {
	n, err := r.r.Read(b)
	if n > 0 {
		// Write the successfully read bytes to the hasher
		// We ignore the return values from Write as hash.Hash.Write never returns an error
		r.hasher.Write(b[:n])
	}

	return n, err
}

// Hash returns the computed hash value of all data that has been read so far.
// This method should typically be called only after all data has been read
// from the TeeReader (i.e., after Read returns io.EOF).
//
// It's safe to call this method multiple times; each call returns the hash
// of all data read up to that point.
func (r TeeReader) Hash() Hash {
	return r.hasher.Sum(nil)
}

// NewTeeReader creates a new TeeReader that reads from the provided io.Reader
// while simultaneously computing the SHA256 hash of the data.
//
// This is useful when you need to:
// - Read data from a source and compute its hash without storing all data in memory
// - Process streaming data where you need both the content and its hash
// - Implement efficient file copying with integrity verification
//
// Usage pattern:
//
//	teeReader := NewTeeReader(file)
//	data, err := io.ReadAll(teeReader)  // or read in chunks
//	hash := teeReader.Hash()
func NewTeeReader(r io.Reader) *TeeReader {
	return &TeeReader{
		r:      r,
		hasher: sha256.New(),
	}
}

// ParseFromBytes validates and creates a Hash from raw bytes.
// The input must be exactly 32 bytes (SHA256 hash size).
//
// This function performs validation to ensure the byte slice represents
// a valid SHA256 hash. It returns an error if the input is nil, empty,
// or not exactly 32 bytes in length.
//
// Parameters:
//
//	hash: byte slice that should contain exactly 32 bytes
//
// Returns:
//
//	Hash: the validated hash value
//	error: validation error if input is invalid
func ParseFromBytes(hash []byte) (Hash, error) {
	if hash == nil {
		return nil, fmt.Errorf("hash: hash bytes cannot be nil")
	}

	if len(hash) != ByteSize {
		return nil, fmt.Errorf("hash: invalid hash size %d, expected %d", len(hash), ByteSize)
	}

	return Hash(hash), nil
}

// ParseFromString parses a hash from its string representation back to a Hash value.
// The input string must be in the exact format produced by Hash.String():
// "sha256-" followed by 64 hexadecimal characters (lowercase).
//
// This function performs comprehensive validation:
// - Checks total string length (must be exactly StringSize)
// - Validates the "sha256-" prefix
// - Validates hexadecimal encoding
// - Ensures the decoded bytes are exactly 32 bytes
//
// Parameters:
//
//	value: string representation of hash (e.g., "sha256-a665a45920...")
//
// Returns:
//
//	Hash: the parsed hash value
//	error: parsing/validation error if input is invalid
//
// Performance note: Uses efficient string slicing instead of string replacement
func ParseFromString(value string) (Hash, error) {
	if len(value) != StringSize {
		return nil, fmt.Errorf("hash: invalid hash string length %d, expected %d", len(value), StringSize)
	}

	if !strings.HasPrefix(value, hashHeader) {
		return nil, fmt.Errorf("hash: invalid hash prefix, expected %q", hashHeader)
	}

	// Use efficient string slicing instead of strings.Replace
	hexPart := value[len(hashHeader):]
	b, err := hex.DecodeString(hexPart)
	if err != nil {
		return nil, fmt.Errorf("hash: invalid hexadecimal encoding: %w", err)
	}

	if len(b) != ByteSize {
		return nil, fmt.Errorf("hash: decoded hash size %d, expected %d", len(b), ByteSize)
	}

	return Hash(b), nil
}

// Print is a utility function similar to fmt.Fprint that writes a formatted
// hash value followed by additional arguments to the specified writer.
//
// The hash is displayed in its short form (last 5 characters) followed
// by the additional arguments. This is useful for logging and debugging
// where you want to include hash information with other data.
// Optimized to avoid slice append allocation.
//
// Parameters:
//
//	w: destination writer (e.g., os.Stdout, log file, buffer)
//	hash: raw hash bytes (should be 32 bytes for SHA256)
//	args: additional arguments to print after the hash
//
// Example output: "a27ae hello world"
func Print(w io.Writer, hash []byte, args ...interface{}) {
	value := Hash(hash)
	// Pre-allocate slice to avoid append allocation
	allArgs := make([]interface{}, 1+len(args))
	allArgs[0] = value.Short()
	copy(allArgs[1:], args)
	fmt.Fprintln(w, allArgs...)
}

// Format is a utility function that converts raw hash bytes to their
// string representation. It handles the nil case gracefully by returning "nil".
//
// This function is useful for logging, debugging, and displaying hash values
// in a consistent format throughout an application.
//
// Parameters:
//
//	value: raw hash bytes (typically 32 bytes for SHA256, but can be nil)
//
// Returns:
//
//	string: formatted hash with "sha256-" prefix, or "nil" if input is nil
//
// Example:
//
//	Format(nil) -> "nil"
//	Format(hashBytes) -> "sha256-a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
func Format(value []byte) string {
	if value == nil {
		return "nil"
	}

	return Hash(value).String()
}
