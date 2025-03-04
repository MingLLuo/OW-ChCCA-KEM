package pkg

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func BenchmarkOwChCCAKEM_GenerateKeyPair(b *testing.B) {
	testParams := ListParameterSets()
	b.ResetTimer()
	for _, paramName := range testParams {
		params, err := GetParameterSet(paramName)
		kem := OwChCCAKEM{Params: params}
		if err != nil {
			b.Fatalf("GetParameterSet failed: %v", err)
		}
		b.Run(params.Name+"/KeyGen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				kem.GenerateKeyPair(rand.Reader)
			}
		})
	}
}

func TestOwChCCAKEM_Decapsulate(t *testing.T) {
	testParam := GetDefaultParameterSet()
	kem := OwChCCAKEM{Params: testParam}
	pk, sk, err := kem.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	ct, ss, err := kem.Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}
	ss2, err := kem.Decapsulate(sk, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if !bytes.Equal(ss, ss2) {
		t.Fatalf("Decapsulated secret does not match")
	}
}
