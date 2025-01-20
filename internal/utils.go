package internal

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

func BigIntToUint64Slice(b *big.Int) []uint64 {
	// Get big.Int bytes (big-endian)
	bytes := b.Bytes()
	fmt.Print("big.Int bytes: ")
	for _, v := range bytes {
		fmt.Printf("%02x ", v)
	}
	// Calculate padding
	length := len(bytes)
	padding := (8 - (length % 8)) % 8
	padded := make([]byte, padding+length)
	copy(padded[padding:], bytes)

	// Convert padded bytes to uint64 slice
	numUint64 := len(padded) / 8
	result := make([]uint64, numUint64)
	for i := 0; i < numUint64; i++ {
		// Read 8 bytes each time and parse to uint64 (little-endian)
		result[i] = binary.LittleEndian.Uint64(padded[i*8 : (i+1)*8])
	}
	return result
}

func Uint64SliceToBigInt(slice []uint64) *big.Int {
	numUint64 := len(slice)
	bytes := make([]byte, numUint64*8)
	for i := 0; i < numUint64; i++ {
		binary.LittleEndian.PutUint64(bytes[i*8:(i+1)*8], slice[i])
	}
	return new(big.Int).SetBytes(bytes)
}

// PrintUint64Slice Print []uint64
func PrintUint64Slice(slice []uint64) {
	for i, v := range slice {
		fmt.Printf("slice[%d] = %d\n", i, v)
	}
}

// PrintBigInt Print big.Int
func PrintBigInt(b *big.Int) {
	fmt.Printf("big.Int: %s\n", b.String())
}

func InitBigIntVec(n int) Vec {
	vec := make([]*big.Int, n)
	for i := range n {
		vec[i] = new(big.Int)
	}
	return vec
}

// VecSumWithMod Calculate the sum of a vector of big.Int with modulo
func VecSumWithMod(vec Vec, mod *big.Int) *big.Int {
	sum := new(big.Int)
	for _, v := range vec {
		sum.Add(sum, v)
		sum.Mod(sum, mod)
	}
	return sum.Mod(sum, mod)
}
