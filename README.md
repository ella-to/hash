# Hash Library

A Go library for SHA256 hash generation and manipulation with a focus on convenience, performance, and type safety.

## Installation

```bash
go get ella.to/hash
```

## Quick Start

```go
package main

import (
    "fmt"
    "ella.to/hash"
)

func main() {
    // Generate hash from bytes
    h := hash.FromBytes([]byte("hello world"))
    fmt.Println(h.String()) // sha256-b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    
    // Short representation for logs
    fmt.Println(h.Short()) // efcde9
}
```

## Usage Examples

### Basic Hash Generation

```go
// From byte slice
data := []byte("hello world")
h := hash.FromBytes(data)

// From string
h = hash.FromBytes([]byte("hello world"))

// From file or any io.Reader
file, _ := os.Open("data.txt")
defer file.Close()
h, err := hash.FromReader(file)
if err != nil {
    log.Fatal(err)
}
```

### Streaming with TeeReader

When you need both the data and its hash without loading everything into memory:

```go
// Using the built-in TeeReader function
file, _ := os.Open("large-file.dat")
defer file.Close()

teeReader, hashFunc := hash.FromTeeReader(file)
data, err := io.ReadAll(teeReader)
if err != nil {
    log.Fatal(err)
}
hashValue := hashFunc()

// Using the custom TeeReader struct for more control
teeReader := hash.NewTeeReader(file)
buffer := make([]byte, 4096)
for {
    n, err := teeReader.Read(buffer)
    if n > 0 {
        // Process buffer[:n]
    }
    if err == io.EOF {
        break
    }
    if err != nil {
        log.Fatal(err)
    }
}
hashValue := teeReader.Hash()
```

### String Parsing and Validation

```go
hashStr := "sha256-b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

// Parse from string
h, err := hash.ParseFromString(hashStr)
if err != nil {
    log.Fatal(err)
}

// Parse from raw bytes
rawBytes := make([]byte, 32) // 32 bytes for SHA256
h, err = hash.ParseFromBytes(rawBytes)
if err != nil {
    log.Fatal(err)
}
```

### JSON Marshaling/Unmarshaling

The `Hash` type implements `encoding.TextMarshaler` and `encoding.TextUnmarshaler`:

```go
type Document struct {
    Content string    `json:"content"`
    Hash    hash.Hash `json:"hash"`
}

doc := Document{
    Content: "hello world",
    Hash:    hash.FromBytes([]byte("hello world")),
}

// Marshal to JSON
jsonData, err := json.Marshal(doc)
if err != nil {
    log.Fatal(err)
}

// Unmarshal from JSON
var newDoc Document
err = json.Unmarshal(jsonData, &newDoc)
if err != nil {
    log.Fatal(err)
}
```

### Utility Functions

```go
// Format hash bytes to string (handles nil gracefully)
var hashBytes []byte = nil
fmt.Println(hash.Format(hashBytes)) // "nil"

hashBytes = make([]byte, 32)
fmt.Println(hash.Format(hashBytes)) // "sha256-..."

// Print hash with additional info
hash.Print(os.Stdout, hashBytes, "file processed successfully")
// Output: a27ae file processed successfully
```

## Thread Safety

All operations in this package are **thread-safe**:

- Hash generation functions can be called concurrently
- Hash value methods (String, Short, etc.) are safe for concurrent access
- TeeReader instances should not be shared between goroutines (standard io.Reader practice)

```go
// Safe concurrent usage
var wg sync.WaitGroup
results := make([]hash.Hash, 100)

for i := 0; i < 100; i++ {
    wg.Add(1)
    go func(index int) {
        defer wg.Done()
        results[index] = hash.FromBytes([]byte(fmt.Sprintf("data-%d", index)))
    }(i)
}
wg.Wait()
```

## Error Handling

The library provides detailed error messages for common failure cases:

```go
// Invalid string format
_, err := hash.ParseFromString("invalid-hash")
// Error: hash: invalid hash string length 12, expected 71

// Invalid hex encoding  
_, err = hash.ParseFromString("sha256-invalid_hex_characters_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
// Error: hash: invalid hexadecimal encoding: encoding/hex: invalid byte: U+007A 'z'

// Wrong byte size
_, err = hash.ParseFromBytes(make([]byte, 16))
// Error: hash: invalid hash size 16, expected 32
```

## Constants

```go
const (
    StringSize = 71  // Total length of string representation
    ByteSize   = 32  // Size of hash in bytes (SHA256 = 256 bits = 32 bytes)
)
```

## Best Practices

1. **Use TeeReader for large files**: When processing large files and need both content and hash
2. **Validate inputs**: Always check errors when parsing hashes from external sources
3. **Use Short() for logging**: Use the short representation in logs to save space
4. **Concurrent processing**: The library is thread-safe, leverage goroutines for parallel processing
5. **Memory efficiency**: Use streaming methods for large datasets

## Common Patterns

### File Integrity Verification

```go
func verifyFile(filename string, expectedHash string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    actualHash, err := hash.FromReader(file)
    if err != nil {
        return err
    }
    
    expected, err := hash.ParseFromString(expectedHash)
    if err != nil {
        return err
    }
    
    if actualHash.String() != expected.String() {
        return fmt.Errorf("hash mismatch: expected %s, got %s", 
            expected.String(), actualHash.String())
    }
    
    return nil
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
