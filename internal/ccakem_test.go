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
	t.Logf("NthRoot of pRing: %d", pRing.NthRoot())
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
	pRing, err := ring.NewRing(8, moduli)
	if err != nil {
		t.Errorf("Error in NewRing: %v", err)
	}
	t.Logf("Modulus: %v", pRing.Modulus())

	pRing, err = ring.NewRing(8, []uint64{17})
	if err != nil {
		t.Errorf("Error in NewRing: %v", err)
	}
	t.Logf("Modulus: %v", pRing.Modulus())
}

func TestSetup(t *testing.T) {
	sp := Setup(cryptoRand.Reader)
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

	pk, sk, sp, err := InitKey(cryptoRand.Reader)
	if err != nil {
		t.Errorf("Error in InitKey: %v", err)
	}
	pkChecker(pk, t)
	skChecker(sk, t)
	spChecker(sp, t)
}

func TestNewKey(t *testing.T) {
	sp := Setup(cryptoRand.Reader)
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

//=== RUN   TestKEMResult
//Encap r: 90
//Encap s: [4311810049 4295032832 1099528470529 256 1103806595073 1103823372288 4311810048 1103806660608 4295032833 4311744513 1099511628032 1103806595073 1103823372544 1103823438080 4294967297 4294967296]
//Encap h0: [0 0 1 1 0 0 0 1]
//Encap h1: [0 1 0 0 0 1 0 0]
//Encap x: [1604591974349678826 1084836438928455761 1521195644117786458 1413406227555577738 2126114512100153986 492959563824367811 1155539173296375466 1543438881563509104 86045893007196376 454744663911275293 1038296209985701119 1141714562393316125 1281598110377299697 1721658469250377902 792987122302573520 351635741379346223 1691274067034615307 911108044124576946 163027057661146678 545464995437207320 1927328275195383831 1863737596390775568 1176921627307333552 1252031518390274504 1429596504183131877 262512463285831527 2062564522932480791 286291568326128194 569319557842624495 283146847398496176 927421169601739105 485851608985552316 41175547815279751 898026728480781555 2170821718308518312 2163843527678877137 363087880801723613 2305238420122881641 527085483082152906 367324419551790918 385660332085401822 296479744087563258 1383026806799994034 1107973427499504048 2013987329808587236 1822145934117940646 945412842884969114 1780095235514657242 738134914552789723 1630351587224935388 811965262283649382 2029704459282894795 107116871010034048 1511145639581614519 1188480932148830167 1558251327850526054 1939151777063063661 1056273990806729502 1281011466598498834 558418036159076054 1485575920422366175 1548232621475473028 1781126211234707324 748762285614506027 21835259269161232 1651898773248731008 1247844903444566408 664538778267929699 405861392546004418 1634774327879849201 778037888448583799 667678866356590324 920144537960572593 208710818529204177 1780517612045451654 36419877805328942 1407692349372873153 268965954516314835 497542203889872350 1848173273103172639 1984311244162043558 1131089135703676260 1795579211621547709 2170380505509790176 2114341811314138533 1453925537680159795 2060513690839107398 1568833664978499785 1003417676216864364 1224109852468654316 1905457365908307470 45338275654935433 897831623683037309 1619029167058642209 802393631828929472 1979942972957465241 1910757226167963501 97281170968924674 1967697557602702255 639639657801943525 2072046493499747339 1386429417324603329 925616647217523817 1178738894905380917 1795551106514798118 1819847143164692951 467754261077032434 1713255689995857065 249360869637735064 60722353546178464 1241355352531559187 1670131446689365100 1318658211159431674 2135940140594030746 111574094456684965 368055366812249152 668379091880348858 99360307695675756 758781028190654221 2077896538598888719 65854899345058110 1639851717243297985 75561589368465767 1281345217919697639 1804644012942910500 1469837682166311980 2238892867665233864 2237351349849013480]
//Encap hatH0: [940967957405318547 962244645757370651 888210924595387611 410540327892034820 758376792240423348 604514844641177851 881531253923348504 9604564842470236]
//Encap hatH1: [940967957405318547 962244645757370652 888210924595387610 410540327892034819 758376792240423348 604514844641177852 881531253923348504 9604564842470235]
//Encap hatK0: [227]
//Encap hatK1: [179]
//Decap round_: [733231240605409526 211326225249578778 1591210002403525250 348605992436921567 335983727134594594 1760861762163126308 883980183819109870 2168446051511496060]
//Decap hatHb: [940967957405318547 962244645757370651 888210924595387611 410540327892034820 758376792240423348 604514844641177851 881531253923348504 9604564842470236]
//Decap hb_: [1 0 1 0 0 0 1 0]
//Decap hatKb: [227]
//Decap r: 90
//Decap hatKnb: [62]
//Decap s: [4311810049 4295032832 1099528470529 256 1103806595073 1103823372288 4311810048 1103806660608 4295032833 4311744513 1099511628032 1103806595073 1103823372544 1103823438080 4294967297 4294967296]
//
