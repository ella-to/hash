package hash_test

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"ella.to/hash"
)

func TestValueStringConverstion(t *testing.T) {
	expectedHashValue := "sha256-2498ad992b02c2f6e21684e8057a01463acad5c75a4e75d095619c556a559e8c"
	hashValue, err := hash.ParseFromString(expectedHashValue)

	assert.NoError(t, err)
	assert.Equal(t, expectedHashValue, hashValue.String())
	assert.Equal(t, hash.ByteSize, len(hashValue))
	assert.Equal(t, hash.StringSize, len(hashValue.String()))
}

func TestJsonMarshalUnMarshal(t *testing.T) {
	expectedHashValue := "sha256-2498ad992b02c2f6e21684e8057a01463acad5c75a4e75d095619c556a559e8c"
	hashValue, err := hash.ParseFromString(expectedHashValue)
	if err != nil {
		t.Fatal(err)
	}

	jsonHashValue, err := hashValue.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	var hashValueFromJson hash.Hash
	err = hashValueFromJson.UnmarshalText(jsonHashValue)
	if err != nil {
		t.Fatal(err)
	}

	if expectedHashValue != hashValueFromJson.String() {
		t.Fatalf("expected %s but got this %s", expectedHashValue, hashValueFromJson.String())
	}
}

func TestStructMarshalUnmarshal(t *testing.T) {
	type testStruct struct {
		HashValue hash.Hash `json:"hash_value"`
	}

	expectedHashValue := hash.FromBytes([]byte("test"))

	b, err := json.Marshal(testStruct{
		HashValue: expectedHashValue,
	})
	if err != nil {
		t.Fatal(err)
	}

	var result testStruct
	err = json.Unmarshal(b, &result)
	if err != nil {
		t.Fatal(err)
	}

	if result.HashValue.String() != expectedHashValue.String() {
		t.Fatalf("expected %s but got this %s", expectedHashValue, result.HashValue.String())
	}
}

// Test edge cases and error conditions
func TestParseFromStringErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "wrong prefix",
			input:   "md5-2498ad992b02c2f6e21684e8057a01463acad5c75a4e75d095619c556a559e8c",
			wantErr: true,
		},
		{
			name:    "invalid hex",
			input:   "sha256-invalid_hex_characters_here_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			wantErr: true,
		},
		{
			name:    "too short",
			input:   "sha256-2498ad",
			wantErr: true,
		},
		{
			name:    "too long",
			input:   "sha256-2498ad992b02c2f6e21684e8057a01463acad5c75a4e75d095619c556a559e8c1234",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := hash.ParseFromString(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseFromBytesErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "nil bytes",
			input:   nil,
			wantErr: true,
		},
		{
			name:    "empty bytes",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "too short",
			input:   make([]byte, 16),
			wantErr: true,
		},
		{
			name:    "too long",
			input:   make([]byte, 64),
			wantErr: true,
		},
		{
			name:    "correct size",
			input:   make([]byte, 32),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := hash.ParseFromBytes(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFromBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "empty input",
			input: []byte{},
		},
		{
			name:  "nil input",
			input: nil,
		},
		{
			name:  "simple text",
			input: []byte("hello world"),
		},
		{
			name:  "binary data",
			input: []byte{0x00, 0x01, 0x02, 0x03, 0xFF},
		},
		{
			name:  "large input",
			input: bytes.Repeat([]byte("a"), 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hash.FromBytes(tt.input)
			assert.Equal(t, hash.ByteSize, len(result))
			assert.NotEmpty(t, result.String())
			assert.Contains(t, result.String(), "sha256-")
		})
	}
}

func TestFromReader(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "empty reader",
			input:   "",
			wantErr: false,
		},
		{
			name:    "simple text",
			input:   "hello world",
			wantErr: false,
		},
		{
			name:    "large input",
			input:   strings.Repeat("a", 10000),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			result, err := hash.FromReader(reader)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, hash.ByteSize, len(result))

				// Verify that FromReader and FromBytes produce same result
				expected := hash.FromBytes([]byte(tt.input))
				assert.Equal(t, expected.String(), result.String())
			}
		})
	}
}

func TestFromTeeReader(t *testing.T) {
	input := "hello world"
	reader := strings.NewReader(input)

	teeReader, hashFunc := hash.FromTeeReader(reader)

	// Read all data
	data, err := io.ReadAll(teeReader)
	assert.NoError(t, err)
	assert.Equal(t, input, string(data))

	// Get hash
	result := hashFunc()
	assert.Equal(t, hash.ByteSize, len(result))

	// Verify hash matches FromBytes
	expected := hash.FromBytes([]byte(input))
	assert.Equal(t, expected.String(), result.String())
}

func TestNewTeeReader(t *testing.T) {
	input := "hello world test data"
	reader := strings.NewReader(input)

	teeReader := hash.NewTeeReader(reader)

	// Read data in chunks
	buffer := make([]byte, 5)
	var readData []byte

	for {
		n, err := teeReader.Read(buffer)
		if n > 0 {
			readData = append(readData, buffer[:n]...)
		}
		if err == io.EOF {
			break
		}
		assert.NoError(t, err)
	}

	assert.Equal(t, input, string(readData))

	// Get hash
	result := teeReader.Hash()
	assert.Equal(t, hash.ByteSize, len(result))

	// Verify hash matches FromBytes
	expected := hash.FromBytes([]byte(input))
	assert.Equal(t, expected.String(), result.String())
}

func TestHashShort(t *testing.T) {
	h := hash.FromBytes([]byte("test"))
	short := h.Short()
	assert.Equal(t, 5, len(short))

	fullString := h.String()
	assert.Equal(t, fullString[len(fullString)-5:], short)
}

func TestHashMarshalText(t *testing.T) {
	h := hash.FromBytes([]byte("test"))

	text, err := h.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, h.String(), string(text))
}

func TestHashUnmarshalTextErrors(t *testing.T) {
	var h hash.Hash

	// Test invalid input
	err := h.UnmarshalText([]byte("invalid"))
	assert.Error(t, err)

	// Test valid input
	validHash := "sha256-2498ad992b02c2f6e21684e8057a01463acad5c75a4e75d095619c556a559e8c"
	err = h.UnmarshalText([]byte(validHash))
	assert.NoError(t, err)
	assert.Equal(t, validHash, h.String())
}

func TestFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: "nil",
		},
		{
			name:  "valid hash bytes",
			input: make([]byte, 32),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hash.Format(tt.input)
			if tt.expected != "" {
				assert.Equal(t, tt.expected, result)
			} else {
				assert.Contains(t, result, "sha256-")
			}
		})
	}
}

func TestPrint(t *testing.T) {
	var buf bytes.Buffer
	hashBytes := make([]byte, 32)

	hash.Print(&buf, hashBytes, "test message")

	output := buf.String()
	assert.NotEmpty(t, output)
	assert.Contains(t, output, "test message")
}

// Concurrent access tests
func TestConcurrentHashGeneration(t *testing.T) {
	const numGoroutines = 100
	const dataSize = 1000

	var wg sync.WaitGroup
	results := make([]hash.Hash, numGoroutines)

	// Generate same hash concurrently
	testData := bytes.Repeat([]byte("a"), dataSize)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index] = hash.FromBytes(testData)
		}(i)
	}

	wg.Wait()

	// All results should be identical
	expected := results[0].String()
	for i, result := range results {
		assert.Equal(t, expected, result.String(), "Hash %d doesn't match", i)
	}
}

func TestConcurrentTeeReaderAccess(t *testing.T) {
	const numGoroutines = 50

	var wg sync.WaitGroup
	results := make([]hash.Hash, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			input := "test data for concurrent access"
			reader := strings.NewReader(input)
			teeReader := hash.NewTeeReader(reader)

			// Read all data
			_, err := io.ReadAll(teeReader)
			require.NoError(t, err)

			results[index] = teeReader.Hash()
		}(i)
	}

	wg.Wait()

	// All results should be identical
	expected := results[0].String()
	for i, result := range results {
		assert.Equal(t, expected, result.String(), "Hash %d doesn't match", i)
	}
}

// Benchmark tests
func BenchmarkFromBytes(b *testing.B) {
	data := []byte("hello world")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash.FromBytes(data)
	}
}

func BenchmarkFromBytesLarge(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash.FromBytes(data)
	}
}

func BenchmarkFromReader(b *testing.B) {
	data := "hello world"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(data)
		hash.FromReader(reader)
	}
}

func BenchmarkHashString(b *testing.B) {
	h := hash.FromBytes([]byte("test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.String()
	}
}

func BenchmarkParseFromString(b *testing.B) {
	hashStr := "sha256-2498ad992b02c2f6e21684e8057a01463acad5c75a4e75d095619c556a559e8c"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash.ParseFromString(hashStr)
	}
}

func BenchmarkTeeReader(b *testing.B) {
	data := strings.Repeat("a", 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := strings.NewReader(data)
		teeReader := hash.NewTeeReader(reader)
		io.ReadAll(teeReader)
		teeReader.Hash()
	}
}

// Additional benchmarks for optimized functions
func BenchmarkFromBytesReuse(b *testing.B) {
	data := []byte("hello world")
	output := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash.FromBytesReuse(data, output)
	}
}

func BenchmarkHashShort(b *testing.B) {
	h := hash.FromBytes([]byte("test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Short()
	}
}

func BenchmarkMarshalText(b *testing.B) {
	h := hash.FromBytes([]byte("test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.MarshalText()
	}
}

func BenchmarkUnmarshalText(b *testing.B) {
	text := []byte("sha256-2498ad992b02c2f6e21684e8057a01463acad5c75a4e75d095619c556a559e8c")
	var h hash.Hash

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.UnmarshalText(text)
	}
}
