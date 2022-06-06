package scprf_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/plzfgme/mfast/internal/scprf"
)

func TestSCPRF(t *testing.T) {
	setList := []string{"A", "B", "C", "D", "E"}
	prf := scprf.NewSCPRF(setList)
	mk := make([]byte, 32)
	rand.Read(mk)
	input := sha256.Sum256([]byte("hello world"))
	mkOut := prf.EvalMK(mk, "B", input[:])
	ck := prf.Constrain(mk, "B")
	ckOut := prf.EvalCK(ck, "B", input[:])
	if bytes.Compare(mkOut, ckOut) != 0 {
		t.Errorf("Evaluation on in-range input should be equal, "+
			"but mk output: %v, ck output: %v", mkOut, ckOut)
	}
	ckOut = prf.EvalCK(ck, "C", input[:])
	if ckOut != nil {
		t.Errorf("Evaluation on out-of-range input should be nil, "+
			"but %v", ckOut)
	}
}
