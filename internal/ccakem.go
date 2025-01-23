package internal

import (
	cryptoRand "crypto/rand"
	"fmt"
	"io"
	"math/big"

	"OW-ChCCA-KEM/internal/sha3"

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
	Zb Mat
	b  bool
	sp *SharedParam
	pk *PublicKey
}

type PublicKey struct {
	U0 Mat
	U1 Mat
	sp *SharedParam
}

// Setup generates n x m BigInt matrix for the key generation, filled with random values
func Setup(rand io.Reader) *SharedParam {
	var ss SharedParam
	pRing, err := ring.NewRing(M, moduli)
	if err != nil {
		panic(err)
	}
	ss.pRing = pRing
	ss.A = InitBigIntMat(N, M)
	uniformSampler := ring.NewUniformSampler(sampling.PRNG(rand), pRing)
	ss.PolyVecA = InitPolyVecWithSampler(N, uniformSampler)
	for i := range N {
		pRing.PolyToBigint(ss.PolyVecA[i], 1, ss.A[i])
	}
	return &ss
}

// InitKey This method will Set up First, then generate a key pair
// TODO: Use Setup then NewKey
func InitKey(rand io.Reader) (*PublicKey, *PrivateKey, *SharedParam, error) {
	var pk PublicKey
	var sk PrivateKey
	var sp SharedParam

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
	sp.pRing = pRing
	p := pRing.Modulus()
	pFloat, _ := p.Float64()

	samplingPRNG := sampling.PRNG(rand)
	gaussianSampler := ring.NewGaussianSampler(samplingPRNG, pRing, ring.DiscreteGaussian{Sigma: Alpha_, Bound: pFloat}, false)

	// with m x Lambda, we will transpose later
	PolyVecZbT := InitPolyVecWithSampler(Lambda, gaussianSampler)
	sk.Zb = InitBigIntMat(M, Lambda)
	for i := range Lambda {
		coefficsT := InitBigIntVec(M)
		pRing.PolyToBigint(PolyVecZbT[i], 1, coefficsT)
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
			pRing.MulCoeffsBarrett(polyVecA[i], PolyVecZbT[j], tmpPoly)
			pRing.PolyToBigint(tmpPoly, 1, coeffics)
			matAz[i][j] = VecSumWithMod(coeffics, p)
		}
	}
	// generate matrix Z_q n x lambda
	matZq := InitBigIntMatWithRand(N, Lambda, rand, p)
	if sk.b {
		pk.U0 = matAz
		pk.U1 = matZq
	} else {
		pk.U0 = matZq
		pk.U1 = matZq
	}

	// generate shared key
	sp.PolyVecA = polyVecA
	sp.A = InitBigIntMat(N, M)
	for i := range N {
		pRing.PolyToBigint(polyVecA[i], 1, sp.A[i])
	}
	pk.sp = &sp
	sk.sp = &sp
	sk.pk = &pk
	return &pk, &sk, &sp, nil
}

func NewKey(rand io.Reader, sp *SharedParam) (*PublicKey, *PrivateKey, error) {
	var pk PublicKey
	var sk PrivateKey
	pk.sp = sp
	sk.sp = sp

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

	pRing := sp.pRing

	p := pRing.Modulus()
	pFloat, _ := p.Float64()
	samplingPRNG := sampling.PRNG(rand)
	gaussianSampler := ring.NewGaussianSampler(samplingPRNG, pRing, ring.DiscreteGaussian{Sigma: Alpha, Bound: pFloat}, false)

	// with Lambda x m, we will transpose later
	PolyVecZbT := InitPolyVecWithSampler(Lambda, gaussianSampler)
	sk.Zb = InitBigIntMat(M, Lambda)
	for i := range Lambda {
		coefficsT := InitBigIntVec(M)
		pRing.PolyToBigint(PolyVecZbT[i], 1, coefficsT)
		for j := range M {
			sk.Zb[j][i] = coefficsT[j]
		}
	}

	// Calculate AZ_b, polyVecA size n x m, polyVecZbT size lambda x m
	polyVecA := sp.PolyVecA
	matAz := InitBigIntMat(N, Lambda)
	for i := range N {
		coeffics := InitBigIntVec(M)
		tmpPoly := pRing.NewPoly()
		for j := range Lambda {
			// Az[i][j] = row i of A * Column j of Zb = Sum(polyVecA[i] * polyVecZbT[j])
			pRing.MulCoeffsBarrett(polyVecA[i], PolyVecZbT[j], tmpPoly)
			pRing.PolyToBigint(tmpPoly, 1, coeffics)
			matAz[i][j] = VecSumWithMod(coeffics, p)
		}
	}

	matZq := InitBigIntMatWithRand(N, Lambda, rand, p)
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

	// Generate A Lambda Bit Integers
	r, _ := cryptoRand.Int(cryptoRand.Reader, big.NewInt(1<<Lambda))
	fmt.Printf("Encap r: %v\n", r)
	rBytes := r.Bytes()
	// (s, rho, h0, h1) = G(r)
	s, rho, h0, h1 := G(r)
	// s = VecSimplify(s, pk.sp.pRing.Modulus())
	e := SampleD(M, Alpha_, rho)
	fmt.Printf("Encap s: %v\n", s)
	fmt.Printf("Encap h0: %v\n", h0)
	fmt.Printf("Encap h1: %v\n", h1)
	// x := A^t * s + e
	pRing := pk.sp.pRing
	matA := pk.sp.A
	p := pRing.Modulus()
	x := InitBigIntVec(M)
	matAt := matA.Transpose()
	for i := range M {
		// x[i] = e[i]
		x[i].Mod(e[i], p)
		// x[i] += A^t[i] * s
		x[i] = BigIntAddMod(x[i], BigIntDotProductMod(matAt[i], s, p), p)
	}
	fmt.Printf("Encap x: %v\n", x)

	roundP2 := new(big.Int).Rsh(p, 1)
	// hatH0 = U0^t * s + h0 round(p/2)
	hatH0 := InitBigIntVec(Lambda)
	matU0T := pk.U0.Transpose()
	for i := range Lambda {
		hatH0[i] = BigIntDotProductMod(matU0T[i], s, p)
		hatH0[i] = BigIntAddMod(hatH0[i], h0[i], roundP2)
	}
	fmt.Printf("Encap hatH0: %v\n", hatH0)

	// hatH1 = U1^t * s + h1 round(p/2)
	hatH1 := InitBigIntVec(Lambda)
	matU1T := pk.U1.Transpose()
	for i := range Lambda {
		hatH1[i] = BigIntDotProductMod(matU1T[i], s, p)
		hatH1[i] = BigIntAddMod(hatH1[i], h1[i], roundP2)
	}
	fmt.Printf("Encap hatH1: %v\n", hatH1)

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

	fmt.Printf("Encap hatK0: %v\n", hatK0)
	fmt.Printf("Encap hatK1: %v\n", hatK1)

	// ct := (c0, c1, x, hatH0, hatH1)
	ct = append(ct, c0...)
	ct = append(ct, c1...)
	for i := range x {
		ct = append(ct, BigIntBytesWithSize(x[i], QLen/8)...)
	}
	for i := range hatH0 {
		ct = append(ct, BigIntBytesWithSize(hatH0[i], QLen/8)...)
	}
	for i := range hatH1 {
		ct = append(ct, BigIntBytesWithSize(hatH1[i], QLen/8)...)
	}
	ss = r.Bytes()
	if len(ct) != CiphertextSize/8 {
		return nil, nil, fmt.Errorf("ciphertext size is not correct %d", len(ct))
	} else if len(ss) != Lambda/8 {
		return nil, nil, fmt.Errorf("shared secret size is not correct %d", len(ss))
	}
	return ct, ss, nil
}

func (sk *PrivateKey) DecapsulateTo(ct []byte) (ss []byte, err error) {
	// ct := (c0, c1, x, hatH0, hatH1)
	c0, c1, x, hatH0, hatH1 := ParseCt(ct)
	p := sk.sp.pRing.Modulus()
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
	fmt.Printf("Decap round_: %v\n", round_)
	hb_ := Round(round_, roundP2, p)
	// hatKb = H(x, hatHb, hb_), R = cb xor hatKb
	hatKb := hash3(x, hatHb, hb_)
	fmt.Printf("Decap hatHb: %v\n", hatHb)
	fmt.Printf("Decap hb_: %v\n", hb_)
	fmt.Printf("Decap hatKb: %v\n", hatKb)
	r_ := make([]byte, Lambda/8)
	for i := range r_ {
		r_[i] = cb[i] ^ hatKb[i]
	}
	r := new(big.Int).SetBytes(r_)
	fmt.Printf("Decap r: %v\n", r)
	s, rho, h0, h1 := G(r)
	if sk.b {
		// b = 1
		hb, hnb = h1, h0
	} else {
		// b = 0
		hb, hnb = h0, h1
	}

	// hatHnb_ = Unb^t * s + hnb round(p/2)
	hatHnb_ := InitBigIntVec(Lambda)
	matUnbT := unb.Transpose()
	for i := range Lambda {
		hatHnb_[i] = BigIntDotProductMod(matUnbT[i], s, p)
		BigIntAddMod(hatHnb_[i], hnb[i], roundP2)
	}
	// hatKnb = H(x,hatHnb_,hnb)
	hatKnb := hash3(x, hatHnb_, hnb)
	fmt.Printf("Decap hatKnb: %v\n", hatKnb)

	// check x = A^t * s + e
	e := SampleD(M, Alpha_, rho)
	fmt.Printf("Decap s: %v\n", s)
	x_ := InitBigIntVec(M)
	matAt := sk.sp.A.Transpose()
	for i := range M {
		x_[i].Mod(e[i], p)
		x_[i] = BigIntAddMod(x_[i], BigIntDotProductMod(matAt[i], s, p), p)
	}
	if !x.Equal(x_) {
		return nil, fmt.Errorf("decap failed, check x = A^t * s + e failed")
	}
	// check hatKnb xor R = cnb
	for i := range cnb {
		if cnb[i] != (hatKnb[i] ^ r_[i]) {
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
	return r_, nil
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
	// hatH0,hatH1 with length of Lambda
	hatH0 = InitBigIntVec(Lambda)
	hatH1 = InitBigIntVec(Lambda)
	for i := range M {
		x[i].SetBytes(ct[(2*Lambda+i*QLen)/8 : (2*Lambda+(i+1)*QLen)/8])
	}
	for i := range Lambda {
		hatH0[i].SetBytes(ct[(2*Lambda+(M+i)*QLen)/8 : (2*Lambda+(M+i+1)*QLen)/8])
	}
	for i := range Lambda {
		hatH1[i].SetBytes(ct[(2*Lambda+(M+Lambda+i)*QLen)/8 : (2*Lambda+(M+Lambda+i+1)*QLen)/8])
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
	h = sha3.New512()
	h.Write(m)
	sBytes := make([]byte, N*(Log2Eta+1)/8)
	sBits := make([]byte, N*(Log2Eta+1))
	s = InitBigIntVec(N)
	rhoBytes := make([]byte, Lambda/8)
	h1Bytes := make([]byte, Lambda/8)
	h1Bits := make([]byte, Lambda)
	h1 = InitBigIntVec(Lambda)
	h2Bytes := make([]byte, Lambda/8)
	h2Bits := make([]byte, Lambda)
	h2 = InitBigIntVec(Lambda)

	Hash4(m, sBytes, rhoBytes, h1Bytes, h2Bytes)
	CopyBitToByte(sBytes, sBits)
	for i := range s {
		s[i].SetBytes(sBits[i*(Log2Eta+1) : (i+1)*(Log2Eta+1)])
	}
	rho = new(big.Int).SetBytes(rhoBytes)
	CopyBitToByte(h1Bytes, h1Bits)
	for i := range h1 {
		h1[i].SetInt64(int64(h1Bits[i]))
	}
	CopyBitToByte(h2Bytes, h2Bits)
	for i := range h2 {
		h2[i].SetInt64(int64(h2Bits[i]))
	}
	return s, rho, h1, h2
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, PublicKeySize/8)
	pk.Pack(buf)
	return buf, nil
}

func (pk *PublicKey) UnmarshalBinary(buf []byte, sp *SharedParam) error {
	if len(buf) != PublicKeySize/8 {
		return fmt.Errorf("invalid length, expected %d, got %d", PublicKeySize/8, len(buf))
	}
	pk.UnPack(buf, sp)
	return nil
}

func (pk *PublicKey) Pack(buf []byte) {
	if len(buf) != PublicKeySize/8 {
		panic("buf must be of length PublicKeySize")
	}

	pk.U0.Pack(buf)
	pk.U1.Pack(buf[UMatrixSize:])
}

func (pk *PublicKey) UnPack(buf []byte, sp *SharedParam) {
	if len(buf) != PublicKeySize/8 {
		panic("buf must be of length PublicKeySize")
	}

	pk.U0 = InitBigIntMat(N, Lambda)
	pk.U1 = InitBigIntMat(N, Lambda)

	pk.U0.Unpack(buf)
	pk.U1.Unpack(buf[UMatrixSize:])
	pk.sp = sp
}

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, PrivateKeySize/8)
	sk.Pack(buf)
	return buf, nil
}

func (sk *PrivateKey) UnmarshalBinary(buf []byte, sp *SharedParam, pk *PublicKey) error {
	if len(buf) != PrivateKeySize/8 {
		return fmt.Errorf("invalid length, expected %d, got %d", PrivateKeySize/8, len(buf))
	}
	sk.UnPack(buf, sp, pk)
	return nil
}

func (sk *PrivateKey) Pack(buf []byte) {
	if len(buf) != PrivateKeySize/8 {
		panic("buf must be of length PrivateKeySize/8")
	}

	sk.Zb.Pack(buf)
	buf[len(buf)-1] = byte(1)
}

func (sk *PrivateKey) UnPack(buf []byte, sp *SharedParam, pk *PublicKey) {
	if len(buf) != PrivateKeySize/8 {
		panic("buf must be of length PrivateKeySize")
	}

	sk.Zb = InitBigIntMat(M, Lambda)
	sk.Zb.Unpack(buf)
	sk.b = buf[len(buf)-1] == 1
	sk.sp = sp
	sk.pk = pk
}

func (sp *SharedParam) MarshalBinary() ([]byte, error) {
	// TODO add length
	buf := make([]byte, 0)
	sp.Pack(buf)
	return buf, nil
}

func (sp *SharedParam) UnmarshalBinary(buf []byte) error {
	sp.UnPack(buf)
	return nil
}

func (sp *SharedParam) Pack(buf []byte) {
	for i := range N {
		bytes, err := sp.PolyVecA[i].MarshalBinary()
		if err != nil {
			panic(err)
		}
		for j := range bytes {
			buf = append(buf, bytes[j])
		}
	}
}

func (sp *SharedParam) UnPack(buf []byte) {
	//if len(buf) != SharedParamSize/8 {
	//	panic("buf must be of length SharedParamSize")
	//}

	sp.A = InitBigIntMat(N, M)
	sp.pRing, _ = ring.NewRing(M, moduli)
	sp.PolyVecA = make([]ring.Poly, N)
	for i := range N {
		err := sp.PolyVecA[i].UnmarshalBinary(buf[i*(len(buf)/N) : (i+1)*(len(buf)/N)])
		if err != nil {
			panic(err)
		}
		sp.pRing.PolyToBigint(sp.PolyVecA[i], 1, sp.A[i])
	}
}
