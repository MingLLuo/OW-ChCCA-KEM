package internal

import (
	"OW-ChCCA-KEM/internal/sha3"
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

// PrintVec Print Vec
func PrintVec(vec Vec) {
	for i, v := range vec {
		fmt.Printf("vec[%d] = %s\n", i, v.String())
	}
}

// PrintMat Print Mat
func PrintMat(mat Mat) {
	for i, v := range mat {
		fmt.Printf("mat[%d]:\n", i)
		PrintVec(v)
	}
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
	// Check if mod is 0
	if mod.Cmp(big.NewInt(0)) == 0 {
		panic("mod is 0")
	}
	sum := new(big.Int)
	for _, v := range vec {
		sum.Add(sum, v)
		sum.Mod(sum, mod)
	}
	return sum.Mod(sum, mod)
}

func BigIntAddMod(a, b, mod *big.Int) *big.Int {
	// Check if mod is 0
	if mod.Cmp(big.NewInt(0)) == 0 {
		panic("mod is 0")
	}
	sum := new(big.Int).Add(a, b)
	return sum.Mod(sum, mod)
}

func BigIntSubMod(a, b, mod *big.Int) *big.Int {
	// Check if mod is 0
	if mod.Cmp(big.NewInt(0)) == 0 {
		panic("mod is 0")
	}
	sub := new(big.Int).Sub(a, b)
	return sub.Mod(sub, mod)
}

func BigIntDotProductMod(a, b Vec, mod *big.Int) *big.Int {
	// Check if mod is 0
	if mod.Cmp(big.NewInt(0)) == 0 {
		panic("mod is 0")
	}
	// Check if a and b have different lengths
	if len(a) != len(b) {
		panic("a and b have different lengths")
	}
	dot := new(big.Int)
	for i := range a {
		BigIntAddMod(dot, new(big.Int).Mul(a[i], b[i]), mod)
	}
	return dot
}

// Round Do componentwise rounding of a vector of big.Int t, to get {0,1}^n
// rounded[i] = 0, closer to 0 than delim,
func Round(t Vec, delim *big.Int) Vec {
	// Check if delim is > 0
	if delim.Cmp(big.NewInt(0)) <= 0 {
		panic("delim <= 0")
	}
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
	// Check if m is empty
	if len(m) == 0 {
		panic("m is empty")
	} else if len(m[0]) == 0 {
		panic("m[0] is empty")
	}
	mT := InitBigIntMat(len(m[0]), len(m))
	for i := range mT {
		for j := range m {
			mT[i][j] = m[j][i]
		}
	}
	return mT
}

func (v Vec) Equal(x Vec) bool {
	if len(v) != len(x) {
		return false
	}
	for i := range v {
		if v[i].Cmp(x[i]) != 0 {
			return false
		}
	}
	return true
}

func (v Vec) Pack(buf []byte) {
	for i, b := range buf {
		v[i].SetUint64(uint64(b))
	}
}

func (v Vec) Unpack(buf []byte) {
	for i, b := range buf {
		v[i].SetUint64(uint64(b))
	}
}

func (m Mat) Pack(buf []byte) {
	for i, v := range m {
		v.Pack(buf[i*len(v) : (i+1)*len(v)])
	}
}

func (m Mat) Unpack(buf []byte) {
	for i, v := range m {
		v.Unpack(buf[i*len(v) : (i+1)*len(v)])
	}
}

func CopyBitToByte(src []byte, dest []byte) {
	if src == nil {
		panic("src is nil")
	}
	if dest == nil {
		panic("dest is nil")
	}
	if len(src)*8 != len(dest) {
		panic("src and dest have different lengths")
	}
	for i, b := range src {
		for j := 0; j < 8; j++ {
			dest[i*8+j] = (b >> uint(j)) & 1
		}
	}
}

func Hash4(initKey, sBytes, rhoBytes, h1Bytes, h2Bytes []byte) {
	sl, rl, h1l, h2l := len(sBytes), len(rhoBytes), len(h1Bytes), len(h2Bytes)
	//if sl*8 != N*(Log2Eta+1) {
	//	panic("sBytes has wrong length")
	//}
	//if rl*8 != Lambda {
	//	panic("rhoBytes has wrong length")
	//}
	//if h1l*8 != Lambda {
	//	panic("h1Bytes has wrong length")
	//}
	//if h2l*8 != Lambda {
	//	panic("h2Bytes has wrong length")
	//}

	// m = H(initKey)
	h := sha3.New256()
	h.Write(initKey)
	m := h.Sum(nil)

	h = sha3.New512()
	h.Write(m)

	// totalLen = sl + rl + h1l + h2l
	totalLen := sl + rl + h1l + h2l
	totalBytes := make([]byte, totalLen)
	h.Read(totalBytes)

	// s = totalBytes[:sl]
	copy(sBytes, totalBytes[:sl])
	// rho = totalBytes[sl:sl+rl]
	copy(rhoBytes, totalBytes[sl:sl+rl])
	// h1 = totalBytes[sl+rl:sl+rl+h1l]
	copy(h1Bytes, totalBytes[sl+rl:sl+rl+h1l])
	// h2 = totalBytes[sl+rl+h1l:sl+rl+h1l+h2l]
	copy(h2Bytes, totalBytes[sl+rl+h1l:sl+rl+h1l+h2l])
}
