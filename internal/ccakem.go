package internal

import (
	"OW-ChCCA-KEM/internal/sha3"
	cryptoRand "crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

type (
	Vec []*big.Int
	Mat []Vec
)

type SharedParam struct {
	pRing *ring.Ring
	// with length of N, each element is a Poly with length of M
	PolyVecA []ring.Poly
	A        Mat
}

type PrivateKey struct {
	pRing      *ring.Ring
	PolyVecZbT []ring.Poly
	Zb         Mat
	b          bool
	sp         *SharedParam
	pk         *PublicKey
}

type PublicKey struct {
	pRing *ring.Ring
	U0    Mat
	U1    Mat
	sp    *SharedParam
}

// Setup generate n x m BigInt matrix for the key generation, filled with random values
func Setup() *SharedParam {
	var ss SharedParam
	pRing, err := ring.NewRing(M, moduli)
	if err != nil {
		panic(err)
	}
	ss.pRing = pRing
	ss.A = make(Mat, N)
	uniformSampler := ring.NewUniformSampler(sampling.PRNG(nil), pRing)
	ss.PolyVecA = InitPolyVecWithSampler(N, uniformSampler)
	for i := range N {
		ss.A[i] = InitBigIntVec(M)
		pRing.PolyToBigint(ss.PolyVecA[i], 1, ss.A[i])
	}
	return &ss
}

// InitKey This method will Set up First, then generate a key pair
func InitKey(rand io.Reader) (*PublicKey, *PrivateKey, *SharedParam, error) {
	var pk PublicKey
	var sk PrivateKey
	var ss SharedParam

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, nil, err
	}

	// generate single bit b
	b := make([]byte, 1)
	if _, err := io.ReadFull(rand, b); err != nil {
		return nil, nil, nil, err
	}
	sk.b = b[0] == 1

	// Z_b <- Gaussian Z_q, alpha with m x lambda
	pRing, err := ring.NewRing(M, moduli)
	if err != nil {
		panic(err)
	}
	pk.pRing = pRing
	sk.pRing = pRing
	ss.pRing = pRing
	p := pRing.Modulus()
	pFloat, _ := p.Float64()

	samplingPRNG := sampling.PRNG(rand)
	gaussianSampler := ring.NewGaussianSampler(samplingPRNG, pRing, ring.DiscreteGaussian{Sigma: Alpha_, Bound: pFloat}, false)

	// with m x Lambda, we will transpose later
	sk.PolyVecZbT = InitPolyVecWithSampler(Lambda, gaussianSampler)
	sk.Zb = InitBigIntMat(M, Lambda)
	for i := range Lambda {
		coefficsT := InitBigIntVec(M)
		pRing.PolyToBigint(sk.PolyVecZbT[i], 1, coefficsT)
		for j := range M {
			sk.Zb[j][i] = coefficsT[j]
		}
	}

	// Generate matrix A in Z_q n x m in random, size of A will be n x m
	// in the following, I will simplify the process
	// 1. use each row of A as a polynomial, multiply with Z_b to get a Vector
	// 2. for each row, calculate the sum mod q to get a Vector(Az_b)
	uniformSampler := ring.NewUniformSampler(samplingPRNG, pRing)
	matAz := InitBigIntMat(N, Lambda)
	polyVecA := InitPolyVecWithSampler(N, uniformSampler)
	for i := range N {
		coeffics := InitBigIntVec(M)
		tmpPoly := pRing.NewPoly()
		for j := range Lambda {
			// Az[i][j] = row i of A * Column j of Zb = Sum(polyVecA[i] * polyVecZbT[j])
			pRing.MulCoeffsBarrett(polyVecA[i], sk.PolyVecZbT[j], tmpPoly)
			pRing.PolyToBigint(tmpPoly, 1, coeffics)
			matAz[i][j] = VecSumWithMod(coeffics, p)
		}
	}
	// generate matrix Z_q n x lambda
	matZq := InitBigIntMat(N, Lambda)
	for i := range N {
		for j := range Lambda {
			matZq[i][j], err = cryptoRand.Int(rand, p)
			if err != nil {
				return nil, nil, nil, err
			}
		}
	}
	if sk.b {
		pk.U0 = matAz
		pk.U1 = matZq
	} else {
		pk.U0 = matZq
		pk.U1 = matZq
	}

	// generate shared key
	ss.PolyVecA = polyVecA
	ss.A = InitBigIntMat(N, M)
	for i := range N {
		pRing.PolyToBigint(polyVecA[i], 1, ss.A[i])
	}
	pk.sp = &ss
	sk.sp = &ss
	sk.pk = &pk
	return &pk, &sk, &ss, nil
}

func NewKey(rand io.Reader, ss SharedParam) (*PublicKey, *PrivateKey, error) {
	var pk PublicKey
	var sk PrivateKey
	pk.sp = &ss
	sk.sp = &ss

	seed := make([]byte, SeedSize)
	_, err := io.ReadFull(rand, seed)
	if err != nil {
		return nil, nil, err
	}

	// generate single bit b
	b := make([]byte, 1)
	if _, err := io.ReadFull(rand, b); err != nil {
		return nil, nil, err
	}
	sk.b = b[0] == 1

	pRing := ss.pRing
	pk.pRing = pRing
	sk.pRing = pRing

	p := pRing.Modulus()
	pFloat, _ := p.Float64()
	samplingPRNG := sampling.PRNG(rand)
	gaussianSampler := ring.NewGaussianSampler(samplingPRNG, pRing, ring.DiscreteGaussian{Sigma: Alpha_, Bound: pFloat}, false)

	// with m x Lambda, we will transpose later
	sk.PolyVecZbT = InitPolyVecWithSampler(Lambda, gaussianSampler)
	sk.Zb = make(Mat, M)
	for i := range M {
		sk.Zb[i] = InitBigIntVec(Lambda)
	}
	for i := range Lambda {
		coefficsT := InitBigIntVec(M)
		pRing.PolyToBigint(sk.PolyVecZbT[i], 1, coefficsT)
		for j := range M {
			sk.Zb[j][i] = coefficsT[j]
		}
	}

	// Calculate AZ_b, polyVecA size n x m, polyVecZbT size lambda x m
	polyVecA := ss.PolyVecA
	matAz := InitBigIntMat(N, Lambda)
	for i := range N {
		coeffics := InitBigIntVec(M)
		tmpPoly := pRing.NewPoly()
		for j := range Lambda {
			// Az[i][j] = row i of A * Column j of Zb = Sum(polyVecA[i] * polyVecZbT[j])
			pRing.MulCoeffsBarrett(polyVecA[i], sk.PolyVecZbT[j], tmpPoly)
			pRing.PolyToBigint(tmpPoly, 1, coeffics)
			matAz[i][j] = VecSumWithMod(coeffics, p)
		}
	}

	matZq := InitBigIntMat(N, Lambda)
	for i := range N {
		for j := range Lambda {
			matZq[i][j], err = cryptoRand.Int(rand, p)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	if sk.b {
		pk.U0 = matAz
		pk.U1 = matZq
	} else {
		pk.U0 = matZq
		pk.U1 = matAz
	}
	sk.pk = &pk

	return &pk, &sk, nil
}

func (pk *PublicKey) EncapsulateTo() (ct []byte, ss []byte, err error) {
	seed := make([]byte, SeedSize)
	if _, err := cryptoRand.Read(seed); err != nil {
		return nil, nil, err
	}
	// generate shared key
	ss = make([]byte, SharedKeySize/8)
	ct = make([]byte, CiphertextSize/8)

	// Generate A Lambda Bit Integers
	r, _ := cryptoRand.Int(io.Reader(nil), big.NewInt(1<<Lambda))
	rBytes := r.Bytes()
	// (s, rho, h0, h1) = G(r)
	s, rho, h0, h1 := G(r)
	e := SampleD(M, Alpha_, rho)
	// x := A^t * s + e
	pRing := pk.pRing
	matA := pk.sp.A
	p := pRing.Modulus()
	x := InitBigIntVec(M)
	matAt := matA.Transpose()
	for i := range M {
		// x[i] = e[i]
		BigIntAddMod(x[i], e[i], p)
		// x[i] += A^t[i] * s
		BigIntAddMod(x[i], BigIntDotProductMod(matAt[i], s, p), p)

	}

	roundP2 := new(big.Int).Rsh(p, 1)
	// hatH0 = U0^t * s + h0 round(p/2)
	hatH0 := InitBigIntVec(N)
	matU0T := pk.U0.Transpose()
	for i := range N {
		hatH0[i] = BigIntDotProductMod(matU0T[i], s, p)
		BigIntAddMod(hatH0[i], h0[i], roundP2)
	}

	// hatH1 = U1^t * s + h1 round(p/2)
	hatH1 := InitBigIntVec(N)
	matU1T := pk.U1.Transpose()
	for i := range N {
		hatH1[i] = BigIntDotProductMod(matU1T[i], s, p)
		BigIntAddMod(hatH1[i], h1[i], roundP2)
	}

	// hatK0 = H(x,hatH0,h0), C0 = hatK0 xor R
	hatK0 := hash3(x, hatH0, h0)
	c0 := make([]byte, Lambda/8)
	for i := range c0 {
		c0[i] = hatK0[i] ^ rBytes[i]
	}

	// hatK1 = H(x,hatH1,h1), C1 = hatK1 xor R
	hatK1 := hash3(x, hatH1, h1)
	c1 := make([]byte, Lambda/8)
	for i := range c1 {
		c1[i] = hatK1[i] ^ rBytes[i]
	}

	// ct := (c0, c1, x, hatH0, hatH1)
	ct = append(ct, c0...)
	ct = append(ct, c1...)
	for i := range x {
		// m x Lambda bits
		ct = append(ct, x[i].Bytes()...)
	}
	for i := range hatH0 {
		ct = append(ct, hatH0[i].Bytes()...)
	}
	for i := range hatH1 {
		ct = append(ct, hatH1[i].Bytes()...)
	}
	ss = r.Bytes()
	return ct, ss, nil
}

func (sk *PrivateKey) DecapsulateTo(ct []byte) (ss []byte, err error) {
	//ct := (c0, c1, x, hatH0, hatH1)
	c0, c1, x, hatH0, hatH1 := ParseCt(ct)
	p := sk.pRing.Modulus()
	roundP2 := new(big.Int).Rsh(p, 1)
	var hatHb, hatHnb Vec
	var hb, hnb Vec
	var cb, cnb []byte
	var _, unb Mat
	if sk.b {
		hatHb, hatHnb = hatH1, hatH0
		cb, cnb = c1, c0
		_, unb = sk.pk.U1, sk.pk.U0
	} else {
		hatHb, hatHnb = hatH0, hatH1
		cb, cnb = c0, c1
		_, unb = sk.pk.U0, sk.pk.U1
	}
	// hb_ = Round(hatHb - Zb^t * x)

	// Zb^t * x, (Lambda x M) * (M x 1) = Lambda x 1
	ZbTx := InitBigIntVec(Lambda)
	matZbT := sk.Zb.Transpose()
	for i := range Lambda {
		ZbTx[i] = BigIntDotProductMod(matZbT[i], x, p)
	}
	// hatHb - Zb^t * x
	round_ := InitBigIntVec(Lambda)
	for i := range Lambda {
		round_[i] = BigIntSubMod(hatHb[i], ZbTx[i], p)
	}
	hb_ := Round(round_, roundP2)
	// hatKb = H(x, hatHb, hb_), R = cb xor hatKb
	hatKb := hash3(x, hatHb, hb_)
	r := make([]byte, Lambda/8)
	for i := range r {
		r[i] = cb[i] ^ hatKb[i]
	}
	s, rho, h0, h1 := G(new(big.Int).SetBytes(r))
	if sk.b {
		// b = 1
		hb, hnb = h1, h0
	} else {
		// b = 0
		hb, hnb = h0, h1
	}

	// hatHnb_ = Unb^t * s + hnb round(p/2)
	hatHnb_ := InitBigIntVec(N)
	matUnbT := unb.Transpose()
	for i := range N {
		hatHnb_[i] = BigIntDotProductMod(matUnbT[i], s, p)
		BigIntAddMod(hatHnb_[i], hnb[i], roundP2)
	}
	// hatKnb = H(x,hatHnb_,hnb)
	hatKnb := hash3(x, hatHnb_, hnb)

	// check x = A^t * s + e
	e := SampleD(M, Alpha_, rho)
	x_ := InitBigIntVec(M)
	matAt := sk.sp.A.Transpose()
	for i := range M {
		BigIntAddMod(x_[i], e[i], p)
		BigIntAddMod(x_[i], BigIntDotProductMod(matAt[i], s, p), p)
	}
	if !x.Equal(x_) {
		return nil, fmt.Errorf("decap failed, check x = A^t * s + e failed")
	}

	// check hatKnb xor R = cnb
	for i := range cnb {
		if cnb[i] != (hatKnb[i] ^ r[i]) {
			return nil, fmt.Errorf("decap failed, check hatKnb xor R = cnb failed")
		}
	}
	// check hb = hb_
	if !hb.Equal(hb_) {
		return nil, fmt.Errorf("decap failed, check hb = hb_ failed")
	}
	// check hatHnb = hatHnb_
	if !hatHnb.Equal(hatHnb_) {
		return nil, fmt.Errorf("decap failed, check hatHnb = hatHnb_ failed")
	}
	return r, nil
}

func hash3(x Vec, hatHb Vec, hb Vec) []byte {
	h := sha3.New256()
	for i := range x {
		h.Write(x[i].Bytes())
	}
	for i := range hatHb {
		h.Write(hatHb[i].Bytes())
	}
	for i := range hb {
		h.Write(hb[i].Bytes())
	}
	return h.Sum(nil)[:Lambda/8]
}

func ParseCt(ct []byte) (c0 []byte, c1 []byte, x Vec, hatH0 Vec, hatH1 Vec) {
	// c0, c1 with length of Lambda/8 bytes
	c0 = ct[:Lambda/8]
	c1 = ct[Lambda/8 : Lambda/4]
	// x with length of M * Lambda/8 bytes
	x = InitBigIntVec(M)
	// hatH0,hatH1 with length of N * Lambda/8 bytes
	hatH0 = InitBigIntVec(N)
	hatH1 = InitBigIntVec(N)
	for i := range M {
		x[i].SetBytes(ct[(i+2)*Lambda/8 : (i+2+1)*Lambda/8])
	}
	for i := range N {
		hatH0[i].SetBytes(ct[(M+2+i)*Lambda/8 : (M+2+i+1)*Lambda/8])
	}
	for i := range N {
		hatH1[i].SetBytes(ct[(M+2+N+i)*Lambda/8 : (M+2+N+i+1)*Lambda/8])
	}
	return c0, c1, x, hatH0, hatH1
}

// G is random oracle, in our case, it is a hash function sha3-256
// each byte only represent one bit
func G(seed *big.Int) (s Vec, rho *big.Int, h1 Vec, h2 Vec) {
	// m = H(seed)
	h := sha3.New256()
	h.Write(seed.Bytes())
	m := h.Sum(nil)
	// (s, rho, h1, h2) = G(m)
	// total length = N * (log2(eta)+1) + 3 Lambda
	// When Lambda = 64, len = 4480 * 7 + 3 * 64 = 31552
	// When Lambda = 16, len = 1024 * 6 + 3 * 16 = 6192
	var key [64]byte
	var result [64]byte
	h = sha3.New512()
	h.Write(m)

	sFlag := false
	sCounter := N * (Log2Eta + 1) / 8
	sBytes := make([]byte, N*(Log2Eta+1)/8)
	s = InitBigIntVec(N)
	tmp := make([][]byte, 3)
	arr := InitBigIntMat(2, Lambda)
	bitsCount := N*(Log2Eta+1) + 3*Lambda
	hashedCount := 0
	for hashedCount < bitsCount {
		h.Read(key[:])
		h.Read(result[:])
		usedResult := 0
		if !sFlag {
			if sCounter >= len(result) {
				copy(sBytes, result[:])
				hashedCount += N * (Log2Eta + 1)
				sCounter -= len(result)
				continue
			} else {
				copy(sBytes, result[:sCounter])
				sFlag = true
				hashedCount += sCounter * 8
				sCounter = 0
				usedResult = sCounter
			}
		}
		for i := range 3 {
			tmp[i] = make([]byte, Lambda)
			usedTmp := 0
			for {
				if Lambda > len(result)-usedResult {
					// Refresh if not enough
					copy(tmp[i], result[usedResult:])
					h.Write(key[:])
					h.Read(key[:])
					h.Read(result[:])
					usedTmp = len(result) - usedResult
					usedResult = 0
				} else {
					copy(tmp[i], result[usedTmp:Lambda])
					hashedCount += Lambda * 8
					usedResult += Lambda
					break
				}
			}
			if i == 0 {
				// rho is a big.Int with length of Lambda
				rho = new(big.Int).SetBytes(tmp[i])
			} else {
				for j := range Lambda {
					arr[i-1][j] = big.NewInt(int64(tmp[i][j]))
				}
			}
		}
	}
	h1, h2 = arr[0], arr[1]
	// Separate sBytes to sBits, then to s[i]
	sBits := make([]byte, N*(Log2Eta+1))
	for i := range sBytes {
		for j := 0; j < 8; j++ {
			sBits[i*8+j] = (sBytes[i] >> j) & 1
		}
	}
	for i := range s {
		s[i].SetBytes(sBits[i*(Log2Eta+1) : (i+1)*(Log2Eta+1)])
	}
	return s, rho, h1, h2
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, PublicKeySize)
	pk.Pack(buf)
	return buf, nil
}

func (pk *PublicKey) Pack(buf []byte) {
	if len(buf) != PublicKeySize {
		panic("buf must be of length PublicKeySize")
	}

	pk.U0.Pack(buf)
	pk.U1.Pack(buf[UMatrixSize:])

}
