package scprf

import (
	"math"
	"math/big"

	"github.com/plzfgme/consprf"
)

type SCPRF struct {
	setMap map[string]int
	exLen  int
	ggm    *consprf.GGM
}

func NewSCPRF(setList []string) *SCPRF {
	setMap := make(map[string]int)
	for i, set := range setList {
		setMap[set] = i
	}
	exLen := int(math.Ceil(math.Log2(float64(len(setMap)))))
	ggm := consprf.NewGGM(exLen + 256)
	return &SCPRF{
		setMap,
		exLen,
		ggm,
	}
}

func (scprf *SCPRF) EvalMK(mk []byte, set string, input []byte) []byte {
	newInput := (&big.Int{}).Add((&big.Int{}).Lsh(big.NewInt(int64(scprf.setMap[set])), 256), (&big.Int{}).SetBytes(input))
	return scprf.ggm.EvalMK(mk, newInput)
}

func (scprf *SCPRF) Constrain(mk []byte, set string) consprf.GGMConstrainedKey {
	a := (&big.Int{}).Add((&big.Int{}).Lsh(big.NewInt(int64(scprf.setMap[set])), 256), big.NewInt(0))
	allOne := make([]byte, 32)
	for i := range allOne {
		allOne[i] = 0xff
	}
	b := (&big.Int{}).Add((&big.Int{}).Lsh(big.NewInt(int64(scprf.setMap[set])), 256), (&big.Int{}).SetBytes(allOne))
	return scprf.ggm.Constrain(mk, a, b)
}

func (scprf *SCPRF) EvalCK(ck consprf.GGMConstrainedKey, set string, input []byte) []byte {
	newInput := (&big.Int{}).Add((&big.Int{}).Lsh(big.NewInt(int64(scprf.setMap[set])), 256), (&big.Int{}).SetBytes(input))
	return scprf.ggm.EvalCK(ck, newInput)
}
