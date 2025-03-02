// Package arithmetic provides matrix and vector operations for OW-ChCCA-KEM
package arithmetic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

var (
	// ErrInvalidDimensions indicates that matrix/vector dimensions are incompatible
	ErrInvalidDimensions = errors.New("invalid dimensions")

	// ErrSerializationError indicates an error during serialization
	ErrSerializationError = errors.New("serialization error")

	// ErrDeserializationError indicates an error during deserialization
	ErrDeserializationError = errors.New("deserialization error")
)

// Vector represents a vector of big.Int Values with operations in a finite field
type Vector struct {
	Values  []*big.Int
	Modulus *big.Int
}

// Matrix represents a matrix of big.Int Values with operations in a finite field
type Matrix struct {
	Rows, Cols int
	Values     [][]*big.Int
	Modulus    *big.Int
}

// NewVector creates a new vector with the specified length and Modulus
func NewVector(length int, modulus *big.Int) *Vector {
	values := make([]*big.Int, length)
	for i := range values {
		values[i] = new(big.Int)
	}
	return &Vector{
		Values:  values,
		Modulus: new(big.Int).Set(modulus),
	}
}

// NewMatrix creates a new matrix with the specified dimensions and Modulus
func NewMatrix(rows, cols int, modulus *big.Int) Matrix {
	values := make([][]*big.Int, rows)
	for i := range values {
		values[i] = make([]*big.Int, cols)
		for j := range values[i] {
			values[i][j] = new(big.Int)
		}
	}
	return Matrix{
		Rows:    rows,
		Cols:    cols,
		Values:  values,
		Modulus: new(big.Int).Set(modulus),
	}
}

// Length returns the length of the vector
func (v *Vector) Length() int {
	return len(v.Values)
}

// Get returns the value at the specified index
func (v *Vector) Get(index int) *big.Int {
	return new(big.Int).Set(v.Values[index])
}

// Set sets the value at the specified index
func (v *Vector) Set(index int, value *big.Int) {
	v.Values[index] = new(big.Int).Mod(value, v.Modulus)
}

// Equal checks if two vectors are equal
func (v *Vector) Equal(other *Vector) bool {
	if v.Length() != other.Length() {
		return false
	}

	for i := range v.Values {
		if v.Values[i].Cmp(other.Values[i]) != 0 {
			return false
		}
	}

	return true
}

// Add adds two vectors
func (v *Vector) Add(other *Vector) (*Vector, error) {
	if v.Length() != other.Length() {
		return nil, ErrInvalidDimensions
	}

	result := NewVector(v.Length(), v.Modulus)
	for i := range v.Values {
		sum := new(big.Int).Add(v.Values[i], other.Values[i])
		result.Values[i] = sum.Mod(sum, v.Modulus)
	}

	return result, nil
}

// Subtract subtracts one vector from another
func (v *Vector) Subtract(other *Vector) (*Vector, error) {
	if v.Length() != other.Length() {
		return nil, ErrInvalidDimensions
	}

	result := NewVector(v.Length(), v.Modulus)
	for i := range v.Values {
		diff := new(big.Int).Sub(v.Values[i], other.Values[i])
		result.Values[i] = diff.Mod(diff, v.Modulus)
	}

	return result, nil
}

// ScalarMultiply multiplies a vector by a scalar
func (v *Vector) ScalarMultiply(scalar *big.Int) (*Vector, error) {
	result := NewVector(v.Length(), v.Modulus)
	for i := range v.Values {
		product := new(big.Int).Mul(v.Values[i], scalar)
		result.Values[i] = product.Mod(product, v.Modulus)
	}

	return result, nil
}

// DotProduct computes the dot product of two vectors
func (v *Vector) DotProduct(other *Vector) (*big.Int, error) {
	if v.Length() != other.Length() {
		return nil, ErrInvalidDimensions
	}

	result := new(big.Int)
	for i := range v.Values {
		product := new(big.Int).Mul(v.Values[i], other.Values[i])
		product.Mod(product, v.Modulus)
		result.Add(result, product)
		result.Mod(result, v.Modulus)
	}

	return result, nil
}

// Sum returns the sum of all elements in the vector
func (v *Vector) Sum() *big.Int {
	sum := new(big.Int)
	for _, val := range v.Values {
		sum.Add(sum, val)
		sum.Mod(sum, v.Modulus)
	}
	return sum
}

// MarshalBinary implements the encoding.BinaryMarshaler interface
func (v *Vector) MarshalBinary() ([]byte, error) {
	// Calculate the size needed for serialization
	elementSize := (v.Modulus.BitLen() + 7) / 8 // Number of bytes needed to represent each element
	totalSize := 4 + v.Length()*elementSize     // 4 bytes for length + space for elements

	// Create the buffer
	buf := make([]byte, totalSize)

	// Write the length
	binary.BigEndian.PutUint32(buf[:4], uint32(v.Length()))

	// Write each element
	for i, val := range v.Values {
		offset := 4 + i*elementSize
		valBytes := val.Bytes()
		// Pad with leading zeros if necessary
		padding := elementSize - len(valBytes)
		if padding < 0 {
			return nil, fmt.Errorf("%w: element too large", ErrSerializationError)
		}
		copy(buf[offset+padding:offset+elementSize], valBytes)
	}

	return buf, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface
func (v *Vector) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("%w: data too short", ErrDeserializationError)
	}

	// Read the length
	length := int(binary.BigEndian.Uint32(data[:4]))

	// Calculate element size
	elementSize := (v.Modulus.BitLen() + 7) / 8

	// Verify that the buffer is large enough
	if len(data) < 4+length*elementSize {
		return fmt.Errorf("%w: data too short for specified length", ErrDeserializationError)
	}

	// Resize the vector if necessary
	if length != v.Length() {
		v.Values = make([]*big.Int, length)
		for i := range v.Values {
			v.Values[i] = new(big.Int)
		}
	}

	// Read each element
	for i := 0; i < length; i++ {
		offset := 4 + i*elementSize
		v.Values[i] = new(big.Int).SetBytes(data[offset : offset+elementSize])
		v.Values[i].Mod(v.Values[i], v.Modulus)
	}

	return nil
}

// EncodedSize returns the size of the encoded vector in bytes
func (v *Vector) EncodedSize() int {
	elementSize := (v.Modulus.BitLen() + 7) / 8
	return 4 + v.Length()*elementSize
}

// Equal checks if two matrices are equal
func (m Matrix) Equal(other Matrix) bool {
	if m.Rows != other.Rows || m.Cols != other.Cols {
		return false
	}

	for i := 0; i < m.Rows; i++ {
		for j := 0; j < m.Cols; j++ {
			if m.Values[i][j].Cmp(other.Values[i][j]) != 0 {
				return false
			}
		}
	}

	return true
}

// Get returns the value at the specified position
func (m Matrix) Get(row, col int) *big.Int {
	return new(big.Int).Set(m.Values[row][col])
}

// Set sets the value at the specified position
func (m Matrix) Set(row, col int, value *big.Int) {
	m.Values[row][col] = new(big.Int).Mod(value, m.Modulus)
}

// Transpose returns the transpose of the matrix
func (m Matrix) Transpose() (Matrix, error) {
	result := NewMatrix(m.Cols, m.Rows, m.Modulus)

	for i := 0; i < m.Rows; i++ {
		for j := 0; j < m.Cols; j++ {
			result.Values[j][i] = new(big.Int).Set(m.Values[i][j])
		}
	}

	return result, nil
}

// Multiply multiplies two matrices
func (m Matrix) Multiply(other Matrix) (Matrix, error) {
	if m.Cols != other.Rows {
		return Matrix{}, ErrInvalidDimensions
	}

	result := NewMatrix(m.Rows, other.Cols, m.Modulus)

	for i := 0; i < m.Rows; i++ {
		for j := 0; j < other.Cols; j++ {
			sum := new(big.Int)
			for k := 0; k < m.Cols; k++ {
				product := new(big.Int).Mul(m.Values[i][k], other.Values[k][j])
				product.Mod(product, m.Modulus)
				sum.Add(sum, product)
				sum.Mod(sum, m.Modulus)
			}
			result.Values[i][j] = sum
		}
	}

	return result, nil
}

// MultiplyVector multiplies a matrix by a vector
func (m Matrix) MultiplyVector(v *Vector) (*Vector, error) {
	if m.Cols != v.Length() {
		return nil, ErrInvalidDimensions
	}

	result := NewVector(m.Rows, m.Modulus)

	for i := 0; i < m.Rows; i++ {
		sum := new(big.Int)
		for j := 0; j < m.Cols; j++ {
			product := new(big.Int).Mul(m.Values[i][j], v.Values[j])
			product.Mod(product, m.Modulus)
			sum.Add(sum, product)
			sum.Mod(sum, m.Modulus)
		}
		result.Values[i] = sum
	}

	return result, nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface
func (m Matrix) MarshalBinary() ([]byte, error) {
	// Calculate the size needed for serialization
	elementSize := (m.Modulus.BitLen() + 7) / 8 // Number of bytes needed to represent each element
	totalSize := 8 + m.Rows*m.Cols*elementSize  // 8 bytes for dimensions + space for elements

	// Create the buffer
	buf := make([]byte, totalSize)

	// Write the dimensions
	binary.BigEndian.PutUint32(buf[:4], uint32(m.Rows))
	binary.BigEndian.PutUint32(buf[4:8], uint32(m.Cols))

	// Write each element
	for i := 0; i < m.Rows; i++ {
		for j := 0; j < m.Cols; j++ {
			index := i*m.Cols + j
			offset := 8 + index*elementSize
			valBytes := m.Values[i][j].Bytes()
			// Pad with leading zeros if necessary
			padding := elementSize - len(valBytes)
			if padding < 0 {
				return nil, fmt.Errorf("%w: element too large", ErrSerializationError)
			}
			copy(buf[offset+padding:offset+elementSize], valBytes)
		}
	}

	return buf, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface
func (m *Matrix) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: data too short", ErrDeserializationError)
	}

	// Read the dimensions
	rows := int(binary.BigEndian.Uint32(data[:4]))
	cols := int(binary.BigEndian.Uint32(data[4:8]))

	// Calculate element size
	elementSize := (m.Modulus.BitLen() + 7) / 8

	// Verify that the buffer is large enough
	if len(data) < 8+rows*cols*elementSize {
		return fmt.Errorf("%w: data too short for specified dimensions", ErrDeserializationError)
	}

	// Resize the matrix if necessary
	if rows != m.Rows || cols != m.Cols {
		*m = NewMatrix(rows, cols, m.Modulus)
	}

	// Read each element
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			index := i*cols + j
			offset := 8 + index*elementSize
			m.Values[i][j] = new(big.Int).SetBytes(data[offset : offset+elementSize])
			m.Values[i][j].Mod(m.Values[i][j], m.Modulus)
		}
	}

	return nil
}

// EncodedSize returns the size of the encoded matrix in bytes
func (m Matrix) EncodedSize() int {
	elementSize := (m.Modulus.BitLen() + 7) / 8
	return 8 + m.Rows*m.Cols*elementSize
}

// GenerateRandomMatrix creates a new matrix filled with random Values
func GenerateRandomMatrix(rows, cols int, modulus *big.Int, randSource io.Reader) (Matrix, error) {
	result := NewMatrix(rows, cols, modulus)

	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			randVal, err := rand(randSource, modulus)
			if err != nil {
				return Matrix{}, fmt.Errorf("failed to generate random value: %w", err)
			}
			result.Values[i][j] = randVal
		}
	}

	return result, nil
}

// GenerateRandomVector creates a new vector filled with random Values
func GenerateRandomVector(length int, modulus *big.Int, randSource io.Reader) (*Vector, error) {
	result := NewVector(length, modulus)

	for i := 0; i < length; i++ {
		randVal, err := rand(randSource, modulus)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random value: %w", err)
		}
		result.Values[i] = randVal
	}

	return result, nil
}

func GenerateSampleDVector(length int, alpha_ float64, rho []byte, modulus *big.Int) (*Vector, error) {
	result := NewVector(length, modulus)
	p := modulus
	pFloat, _ := p.Float64()
	d := ring.DiscreteGaussian{Sigma: alpha_, Bound: pFloat}
	prng, err := sampling.NewKeyedPRNG(rho)
	if err != nil {
		return nil, err
	}
	newRing, err := ring.NewRing(length, []uint64{modulus.Uint64()})
	if err != nil {
		return nil, err
	}
	sampler, err := ring.NewSampler(prng, newRing, d, false)
	if err != nil {
		return nil, err
	}
	pol := sampler.ReadNew()
	newRing.PolyToBigint(pol, 1, result.Values)
	return result, nil
}

// rand generates a random value in the range [0, Modulus-1]
func rand(randSource io.Reader, modulus *big.Int) (*big.Int, error) {
	// The number of bytes needed to represent numbers up to Modulus
	numBytes := (modulus.BitLen() + 7) / 8
	buf := make([]byte, numBytes)

	for {
		_, err := io.ReadFull(randSource, buf)
		if err != nil {
			return nil, err
		}

		// Ensure the most significant bit is zero to avoid bias
		buf[0] &= 0x7F

		// Convert to big.Int and check if it's in range
		val := new(big.Int).SetBytes(buf)
		if val.Cmp(modulus) < 0 {
			return val, nil
		}

		// Try again if the value is out of range
	}
}

// MarshalVectorSlice marshals a slice of vectors
func MarshalVectorSlice(vectors []*Vector) ([]byte, error) {
	if len(vectors) == 0 {
		return []byte{0, 0, 0, 0}, nil
	}

	// All vectors should have the same length and Modulus
	vecLen := vectors[0].Length()
	modulus := vectors[0].Modulus

	// Calculate the size needed for serialization
	elementSize := (modulus.BitLen() + 7) / 8        // Number of bytes needed to represent each element
	totalSize := 8 + len(vectors)*vecLen*elementSize // 8 bytes for dimensions + space for elements

	// Create the buffer
	buf := bytes.NewBuffer(make([]byte, 0, totalSize))

	// Write the dimensions
	err := binary.Write(buf, binary.BigEndian, uint32(len(vectors)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}

	err = binary.Write(buf, binary.BigEndian, uint32(vecLen))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}

	// Write each vector
	for _, vec := range vectors {
		if vec.Length() != vecLen {
			return nil, fmt.Errorf("%w: vectors have different lengths", ErrSerializationError)
		}

		for j := 0; j < vecLen; j++ {
			valBytes := vec.Values[j].Bytes()
			// Pad with leading zeros if necessary
			padding := elementSize - len(valBytes)
			if padding > 0 {
				_, err := buf.Write(make([]byte, padding))
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
				}
			} else if padding < 0 {
				return nil, fmt.Errorf("%w: element too large", ErrSerializationError)
			}
			_, err := buf.Write(valBytes)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
			}
		}
	}

	return buf.Bytes(), nil
}

// UnmarshalVectorSlice unmarshals a slice of vectors
func UnmarshalVectorSlice(data []byte, modulus *big.Int) ([]*Vector, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("%w: data too short", ErrDeserializationError)
	}

	// Read the dimensions
	numVecs := int(binary.BigEndian.Uint32(data[:4]))
	vecLen := int(binary.BigEndian.Uint32(data[4:8]))

	// Calculate element size
	elementSize := (modulus.BitLen() + 7) / 8

	// Verify that the buffer is large enough
	if len(data) < 8+numVecs*vecLen*elementSize {
		return nil, fmt.Errorf("%w: data too short for specified dimensions", ErrDeserializationError)
	}

	// Create the result slice
	result := make([]*Vector, numVecs)

	// Read each vector
	for i := 0; i < numVecs; i++ {
		result[i] = NewVector(vecLen, modulus)

		for j := 0; j < vecLen; j++ {
			index := i*vecLen + j
			offset := 8 + index*elementSize
			result[i].Values[j] = new(big.Int).SetBytes(data[offset : offset+elementSize])
			result[i].Values[j].Mod(result[i].Values[j], modulus)
		}
	}

	return result, nil
}

func InitPolyVecWithSampler(n int, sampler ring.Sampler) []ring.Poly {
	polyVec := make([]ring.Poly, n)
	for i := range n {
		polyVec[i] = sampler.ReadNew()
	}
	return polyVec
}
