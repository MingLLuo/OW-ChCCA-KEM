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

	PrintBigInt(newBigInt)
}
