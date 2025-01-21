package internal

import (
	"encoding/binary"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/ring"
	"math/big"
)

func InitPolyVecWithSampler(n int, sampler ring.Sampler) []ring.Poly {
	polyVec := make([]ring.Poly, n)
	for i := range n {
		polyVec[i] = sampler.ReadNew()
	}
	return polyVec
}

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

func InitBigIntMat(n, m int) Mat {
	mat := make([]Vec, n)
	for i := range n {
		mat[i] = InitBigIntVec(m)
	}
	return mat
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

func BigIntAddMod(a, b, mod *big.Int) *big.Int {
	sum := new(big.Int).Add(a, b)
	return sum.Mod(sum, mod)
}

func BigIntDotProductMod(a, b Vec, mod *big.Int) *big.Int {
	dot := new(big.Int)
	for i := range a {
		BigIntAddMod(dot, new(big.Int).Mul(a[i], b[i]), mod)
	}
	return dot
}

// Round Do componentwise rounding of a vector of big.Int t, to get {0,1}^n
// rounded[i] = 0, closer to 0 than delim,
func Round(t Vec, delim *big.Int) Vec {
	rounded := InitBigIntVec(len(t))
	for i, v := range t {
		toDelim := new(big.Int).Sub(v, delim)
		if toDelim.Cmp(v) > 0 {
			// closer to 0 than delim, rounded[i] = 0
			rounded[i].SetInt64(0)
		} else {
			rounded[i].SetInt64(1)
		}
	}
	return rounded
}

func (m Mat) Transpose() Mat {
	mT := InitBigIntMat(len(m[0]), len(m))
	for i := range mT {
		for j := range m {
			mT[i][j] = m[j][i]
		}
	}
	return mT
}
