package owchcca

import "testing"

func TestDecapsulate(t *testing.T) {
	sp := Setup()
	pk, sk, err := GenerateNewKeyPair(*sp)
	if err != nil {
		t.Errorf("Error in GenerateNewKeyPair: %v", err)
	}
	ct, ss1, err := Encapsulate(*pk)
	if err != nil {
		t.Errorf("Error in Encapsulate: %v", err)
	}
	ss2, err := Decapsulate(*sk, ct)
	if err != nil {
		t.Errorf("Error in Decapsulate: %v", err)
	}
	if len(ss1) != len(ss2) {
		t.Errorf("Expected ss1 and ss2 to have the same length")
	}
	for i := range ss1 {
		if ss1[i] != ss2[i] {
			t.Errorf("Expected ss1 and ss2 to be equal")
		}
	}
}

func TestBytesDecoding(t *testing.T) {
	sp := Setup()
	spBytes, err := MarshalSharedParam(*sp)
	if err != nil {
		t.Errorf("Error in MarshalSharedParam: %v", err)
	}
	spRes, err := UnmarshalSharedParam(spBytes)
	if err != nil {

	}
	pk, sk, err := GenerateNewKeyPair(spRes)
	if err != nil {
		t.Errorf("Error in GenerateNewKeyPair: %v", err)
	}
	pkBytes, err := MarshalBinaryPublicKey(*pk)
	if err != nil {
		t.Errorf("Error in MarshalBinaryPublicKey: %v", err)
	}
	pkRes, err := UnmarshalBinaryPublicKey(pkBytes, *sp)
	if err != nil {
		t.Errorf("Error in UnmarshalBinaryPublicKey: %v", err)
	}
	ct, ss1, err := Encapsulate(pkRes)
	if err != nil {
		t.Errorf("Error in Encapsulate: %v", err)
	}

	skBytes, err := MarshalBinaryPrivateKey(*sk)
	if err != nil {
		t.Errorf("Error in MarshalBinaryPrivateKey: %v", err)
	}
	skRes, err := UnmarshalBinaryPrivateKey(skBytes, *pk, *sp)
	if err != nil {
		t.Errorf("Error in UnmarshalBinaryPrivateKey: %v", err)
	}

	ss2, err := Decapsulate(skRes, ct)
	if err != nil {
		t.Errorf("Error in Decapsulate: %v", err)
	}
	if len(ss1) != len(ss2) {
		t.Errorf("Expected ss1 and ss2 to have the same length")
	}
	for i := range ss1 {
		if ss1[i] != ss2[i] {
			t.Errorf("Expected ss1 and ss2 to be equal")
		}
	}
}
