package internal

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/MingLLuo/OW-ChCCA-KEM/internal/sha3"

	"github.com/tuneinsight/lattigo/v6/ring"
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

func InitBigIntMatWithRand(n int, m int, rand io.Reader, mod *big.Int) Mat {
	mat := InitBigIntMat(n, m)
	for i := range n {
		for j := range m {
			var err error
			mat[i][j], err = cryptoRand.Int(rand, mod)
			if err != nil {
				panic(err)
			}
		}
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
		dot = BigIntAddMod(dot, new(big.Int).Mul(a[i], b[i]), mod)
	}
	return dot
}

// Round Do componentwise rounding of a vector of big.Int t, to get {0,1}^n
// rounded[i] = 0, closer to 0 than delim, in mod view
func Round(t Vec, delim *big.Int, mod *big.Int) Vec {
	// Check if delim is > 0
	if delim.Cmp(big.NewInt(0)) <= 0 {
		panic("delim <= 0")
	}
	rounded := InitBigIntVec(len(t))
	for i, v := range t {
		if v.Cmp(delim) > 0 {
			// 0 | delim | v | mod
			// toDelim = v - delim
			// toMod = mod - v
			toDelim := new(big.Int).Sub(v, delim)
			toMod := new(big.Int).Sub(mod, v)
			if toDelim.Cmp(toMod) > 0 {
				// closer to mod than delim
				rounded[i].SetInt64(0)
			} else {
				rounded[i].SetInt64(1)
			}
		} else if v.Cmp(delim) < 0 {
			// 0 | v | delim | mod
			// toDelim = delim - v
			toDelim := new(big.Int).Sub(delim, v)
			if toDelim.Cmp(v) > 0 {
				// closer to zero than delim
				rounded[i].SetInt64(0)
			} else {
				rounded[i].SetInt64(1)
			}
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

func (m Mat) MulVec(v Vec, mod *big.Int) Vec {
	// Check if m is empty
	if len(m) == 0 {
		panic("m is empty")
	} else if len(m[0]) == 0 {
		panic("m[0] is empty")
	}
	// Check if v is empty
	if len(v) == 0 {
		panic("v is empty")
	}
	// Check if m and v have different lengths
	if len(m[0]) != len(v) {
		panic("m and v have different lengths")
	}
	result := InitBigIntVec(len(m))
	for i, row := range m {
		result[i] = BigIntDotProductMod(row, v, mod)
	}
	return result
}

func (m Mat) MulMat(n Mat, mod *big.Int) Mat {
	// Check if m is empty
	if len(m) == 0 {
		panic("m is empty")
	} else if len(m[0]) == 0 {
		panic("m[0] is empty")
	}
	// Check if n is empty
	if len(n) == 0 {
		panic("n is empty")
	}
	// Check if m and n have different lengths
	if len(m[0]) != len(n) {
		panic("m and n have different lengths")
	}
	result := InitBigIntMat(len(m), len(n[0]))
	for i, row := range m {
		for j, col := range n.Transpose() {
			result[i][j] = BigIntDotProductMod(row, col, mod)
		}
	}
	return result
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

func (v Vec) Pack() (buf []byte) {
	buf = make([]byte, len(v)*QLen/8)
	for i := range v {
		v[i].FillBytes(buf[i*QLen/8 : (i+1)*QLen/8])
	}
	return buf
}

func (v Vec) Unpack(buf []byte) {
	for i := range v {
		v[i].SetBytes(buf[i*QLen/8 : (i+1)*QLen/8])
	}
}

func (m Mat) Pack() (buf []byte) {
	for _, v := range m {
		buf = append(buf, v.Pack()...)
	}
	return buf
}

func (m Mat) Unpack(buf []byte) {
	for i, v := range m {
		v.Unpack(buf[i*len(v)*QLen/8 : (i+1)*len(v)*QLen/8])
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

func VecSimplify(vec Vec, mod *big.Int) Vec {
	simplified := make(Vec, len(vec))
	for i, v := range vec {
		simplified[i] = new(big.Int).Mod(v, mod)
	}
	return simplified
}

func BigIntBytesWithSize(b *big.Int, size int) []byte {
	bytes := b.Bytes()
	if len(bytes) > size {
		panic("b is too large")
	}
	tmp := make([]byte, size)
	return b.FillBytes(tmp)
}

func BytesToVecWithSize(bytes []byte, length int, size int) Vec {
	if len(bytes)%size != 0 {
		panic("bytes has wrong length")
	}
	vec := InitBigIntVec(length)
	for i := range vec {
		vec[i].SetBytes(bytes[i*size : (i+1)*size])
	}
	return vec
}

func (v Vec) BytesWithSize(size int) []byte {
	bytes := make([]byte, 0)
	for _, b := range v {
		bytes = append(bytes, BigIntBytesWithSize(b, size)...)
	}
	return bytes
}

func (v Vec) RestoreBigIntVec(b []byte) {
	vLen := len(v)
	size := len(b) / vLen
	if len(b)%vLen != 0 {
		panic("b has wrong length")
	}
	for i := range v {
		v[i].SetBytes(b[i*size : (i+1)*size])
	}
}
