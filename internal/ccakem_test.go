package internal

import (
	"testing"
)

func TestParam(t *testing.T) {
	// Print size of moduli
	t.Logf("Size of moduli: %d", len(moduli))
	// Put moduli into a ring, then print the modulus

}

func TestSetup(t *testing.T) {
	sp := Setup()
	// Check A size
	if len(sp.A) != N {
		t.Errorf("Expected A size to be %d, got %d", N, len(sp.A))
	} else if len(sp.A[0]) != M {
		t.Errorf("Expected A[0] size to be %d, got %d", M, len(sp.A[0]))
	}
	// Check bit size of pRing
	//pRing := sp.pRing.M
	mod := sp.pRing.Modulus()
	t.Logf("Modulus bitsize: %d", mod.BitLen())

	// Check the size of pRing
	pRing := sp.pRing
	t.Logf("Level of pRing: %d", pRing.NthRoot())
	// Check Length of polyVecA
	if len(sp.PolyVecA) != N {
		t.Errorf("Expected PolyVecA size to be %d, got %d", N, len(sp.PolyVecA))
	}
	tmp := InitBigIntVec(M)
	pRing.PolyToBigint(sp.PolyVecA[0], 1, tmp)
	PrintVec(tmp)
}
