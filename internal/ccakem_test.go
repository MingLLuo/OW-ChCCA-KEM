package internal

import (
	cryptoRand "crypto/rand"
	"math/big"
	"testing"

	"github.com/tuneinsight/lattigo/v6/ring"
)

func spChecker(sp *SharedParam, t *testing.T) {
	if sp == nil {
		t.Errorf("sp is nil")
	}
	// Check A size
	if len(sp.A) != N {
		t.Errorf("Expected A size to be %d, got %d", N, len(sp.A))
	} else if len(sp.A[0]) != M {
		t.Errorf("Expected A[0] size to be %d, got %d", M, len(sp.A[0]))
	}
	// Check bit size of pRing
	// pRing := sp.pRing.M
	mod := sp.pRing.Modulus()
	t.Logf("Modulus bitsize: %d", mod.BitLen())

	// Check the size of pRing
	pRing := sp.pRing
	t.Logf("Level of pRing: %d", pRing.NthRoot())
	// Check Length of polyVecA
	if len(sp.PolyVecA) != N {
		t.Errorf("Expected PolyVecA size to be %d, got %d", N, len(sp.PolyVecA))
	}
}

func pkChecker(pk *PublicKey, t *testing.T) {
	// Check pk size
	if pk == nil {
		t.Errorf("pk is nil")
	}
	if pk.U0 == nil || pk.U1 == nil {
		t.Errorf("U0 or U1 is nil")
	}
	if pk.sp == nil {
		t.Errorf("Expected sp to be non-nil")
	}
	// U0/U1 size check
	if len(pk.U0) != N {
		t.Errorf("Expected U0 size to be %d, got %d", N, len(pk.U0))
	} else if len(pk.U0[0]) != Lambda {
		t.Errorf("Expected U0[0] size to be %d, got %d", Lambda, len(pk.U0[0]))
	}
	if len(pk.U1) != N {
		t.Errorf("Expected U1 size to be %d, got %d", N, len(pk.U1))
	} else if len(pk.U1[0]) != Lambda {
		t.Errorf("Expected U1[0] size to be %d, got %d", Lambda, len(pk.U1[0]))
	}
}

func skChecker(sk *PrivateKey, t *testing.T) {
	if sk == nil {
		t.Errorf("sk is nil")
	}
	if sk.Zb == nil {
		t.Errorf("Zb is nil")
	}
	// Zb size check
	if len(sk.Zb) != M {
		t.Errorf("Expected Zb size to be %d, got %d", M, len(sk.Zb))
	} else if len(sk.Zb[0]) != Lambda {
		t.Errorf("Expected Zb[0] size to be %d, got %d", N, len(sk.Zb[0]))
	}

	if sk.sp == nil {
		t.Errorf("Expected sp to be non-nil")
	} else if sk.pk == nil {
		t.Errorf("Expected pk to be non-nil")
	}
}

func vecEqualChecker(a, b Vec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Cmp(b[i]) != 0 {
			return false
		}
	}
	return true
}

func TestParam(t *testing.T) {
	// Print size of moduli
	t.Logf("Size of moduli: %d", len(moduli))
	// Put moduli into a ring, then print the modulus
	pRing, _ := ring.NewRing(1, moduli)
	t.Logf("Modulus: %v", pRing.Modulus())
}

func TestSetup(t *testing.T) {
	sp := Setup()
	spChecker(sp, t)
	tmp := InitBigIntVec(M)
	sp.pRing.PolyToBigint(sp.PolyVecA[0], 1, tmp)
	PrintVec(tmp)
}

func TestInitKey(t *testing.T) {
	// Check rand nil fails, use recover
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Logf("InitKey did not panic")
			}
		}()
		_, _, _, _ = InitKey(nil)
	}()

	pk, sk, sp, _ := InitKey(cryptoRand.Reader)
	pkChecker(pk, t)
	skChecker(sk, t)
	spChecker(sp, t)
}

func TestNewKey(t *testing.T) {
	sp := Setup()
	pk, sk, err := NewKey(cryptoRand.Reader, sp)
	if err != nil {
		t.Errorf("Error in NewKey: %v", err)
	}
	pkChecker(pk, t)
	skChecker(sk, t)
}

func TestParseCt(t *testing.T) {
	ct := make([]byte, CiphertextSize/8)
	for i := range ct {
		ct[i] = byte(i)
	}
	c0, c1, x, hatH0, hatH1 := ParseCt(ct)
	if c0 == nil || c1 == nil || x == nil || hatH0 == nil || hatH1 == nil {
		t.Errorf("Expected c0, c1, x, hatH0, hatH1 to be non-nil")
	}
	if len(c0) != Lambda/8 {
		t.Errorf("Expected c0 size to be %d, got %d", Lambda/8, len(c0))
	}
	if len(c1) != Lambda/8 {
		t.Errorf("Expected c1 size to be %d, got %d", Lambda/8, len(c1))
	}
	if len(x) != M {
		t.Errorf("Expected x size to be %d, got %d", M, len(x))
	} else if len(x[0].Bytes()) != QLen/8 {
		t.Errorf("Expected x[0] size to be %d, got %d", QLen/8, len(x[0].Bytes()))
	}
	if len(hatH0) != Lambda {
		t.Errorf("Expected hatH0 size to be %d, got %d", Lambda, len(hatH0))
	} else if len(hatH0[0].Bytes()) != QLen/8 {
		t.Errorf("Expected hatH0[0] size to be %d, got %d", QLen/8, len(hatH0[0].Bytes()))
	}
	if len(hatH1) != Lambda {
		t.Errorf("Expected hatH1 size to be %d, got %d", Lambda, len(hatH1))
	} else if len(hatH1[0].Bytes()) != QLen/8 {
		t.Errorf("Expected hatH1[0] size to be %d, got %d", QLen/8, len(hatH1[0].Bytes()))
	}
}

func TestG(t *testing.T) {
	// Check G can generate the same result when called twice
	seedBytes := make([]byte, 32)
	for i := range seedBytes {
		seedBytes[i] = byte(i)
	}
	seed := new(big.Int).SetBytes(seedBytes)
	s1, rho1, h11, h21 := G(seed)
	if s1 == nil {
		t.Errorf("s1 is nil")
	} else if len(s1) != N {
		t.Errorf("Expected s1 size to be %d, got %d", N, len(s1))
	}
	if rho1 == nil {
		t.Errorf("rho1 is nil")
	}
	// Pass the rho size check, since {0, 1}^Lambda will make arbitrary size big.Int
	if h11 == nil {
		t.Errorf("h11 is nil")
	} else if len(h11) != Lambda {
		t.Errorf("Expected h11 size to be %d, got %d", Lambda, len(h11))
	}
	if h21 == nil {
		t.Errorf("h21 is nil")
	} else if len(h21) != Lambda {
		t.Errorf("Expected h21 size to be %d, got %d", Lambda, len(h21))
	}

	s2, rho2, h12, h22 := G(seed)
	if vecEqualChecker(s1, s2) == false {
		t.Errorf("s1 != s2")
	}
	if rho1.Cmp(rho2) != 0 {
		t.Errorf("rho1 != rho2")
	}
	if vecEqualChecker(h11, h12) == false {
		t.Errorf("h11 != h12")
	}
	if vecEqualChecker(h21, h22) == false {
		t.Errorf("h21 != h22")
	}
}

func TestKEMResult(t *testing.T) {
	pk, sk, _, _ := InitKey(cryptoRand.Reader)
	ct, ss, err := pk.EncapsulateTo()
	if err != nil {
		t.Errorf("Error in EncapsulateTo: %v", err)
	}
	ss2, err := sk.DecapsulateTo(ct)
	if err != nil {
		t.Errorf("Error in DecapsulateTo: %v", err)
	}
	if len(ss) != len(ss2) {
		t.Errorf("Expected ss size to be %d, got %d", len(ss), len(ss2))
	} else {
		for i := range ss {
			if ss[i] != ss2[i] {
				t.Errorf("ss[%d] != ss2[%d]", i, i)
			}
		}
	}
}
