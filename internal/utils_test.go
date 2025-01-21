package internal

import (
	"fmt"
	"testing"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

func TestBigIntToUint64Slice(t *testing.T) {
	b := bignum.NewInt("7484165189517896027318192121767201416039872004910529422703501933303497309177247161202453673508851750059292999942026203470027056226694857512284815420448467")
	uint64Slice := BigIntToUint64Slice(b)
	PrintUint64Slice(uint64Slice)
	newBigInt := Uint64SliceToBigInt(uint64Slice)
	PrintBigInt(newBigInt)
	PrintBigInt(b)
}

func TestBigIntToUint64Slice1(t *testing.T) {
	newRing, err := ring.NewRing(16, Qi60[:2])
	if err != nil {
		fmt.Print(err)
	}
	newBigInt := newRing.Modulus()
	fmt.Printf("length of newBigInt: %v\n", len(newBigInt.Bytes()))
	uint64Slice := BigIntToUint64Slice(newBigInt)
	fmt.Printf("length of uint64Slice: %v\n", len(uint64Slice))
	coeffs := newRing.NewPoly().Coeffs
	// print length of coeffs
	fmt.Printf("length of coeffs: %v\n", len(coeffs))
	fmt.Printf("length of coeffs[0]: %v\n", len(coeffs[0]))
	PrintBigInt(newBigInt)
}

func TestVecSumWithMod(t *testing.T) {
	// Test Empty Vec
	emptyVec := InitBigIntVec(0)
	emptySum := VecSumWithMod(emptyVec, bignum.NewInt("1"))
	if emptySum.Int64() != 0 {
		t.Errorf("emptySum != 0")
	}

	// Test Vec with 10 elements
	vec := InitBigIntVec(10)
	for i := range vec {
		vec[i] = bignum.NewInt(i)
	}
	sum := VecSumWithMod(vec, bignum.NewInt("10"))
	if sum.Int64() != 5 {
		t.Errorf("sum != 0")
	}
}
