package internal

import (
	"math/rand"
)

// SeededReader implements the io.Reader interface and generates deterministic random data
// based on a fixed seed.
type SeededReader struct {
	rand *rand.Rand
}

// NewSeededReader creates a new SeededReader with a fixed seed.
func NewSeededReader(seed int64) *SeededReader {
	return &SeededReader{
		rand: rand.New(rand.NewSource(seed)), // Create a deterministic random generator
	}
}

// Read generates random bytes based on the fixed seed and writes them into the provided buffer.
func (sr *SeededReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(sr.rand.Intn(256)) // Generate a random byte between 0 and 255
	}
	return len(p), nil // Always fill the buffer completely
}
