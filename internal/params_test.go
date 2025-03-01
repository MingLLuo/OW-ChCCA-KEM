package internal

import (
	"testing"

	"github.com/kr/pretty"
)

func TestCalculateParameters(t *testing.T) {
	param := CalculateParameters(128)
	if err := param.Validate(); err != nil {
		t.Errorf("Error in Validate: %v", err)
	}
	pretty.Println(param)

	// Set p to []uint64 from param.Lattice
	println("param.LatticeParams.Q:" + param.LatticeParams.Q.String())
}
