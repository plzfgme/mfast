package mfast

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/fentec-project/gofe/abe"
	"github.com/plzfgme/mfast/internal/scprf"
)

type Searcher struct {
	scPRF *scprf.SCPRF
	aBE   *abe.FAME
	keys  *DelegatedKeys
}

type SearcherConfig struct {
	setList []string
	keys    *DelegatedKeys
}

func NewSearcher(config *SearcherConfig) *Searcher {
	scPRF := scprf.NewSCPRF(config.setList)
	aBE := abe.NewFAME()
	return &Searcher{
		scPRF: scPRF,
		aBE:   aBE,
		keys:  config.keys,
	}
}

func (searcher *Searcher) GenPreSearchTkn(set string, w []byte) *PreSearchToken {
	return &PreSearchToken{
		TW: searcher.scPRF.EvalCK(searcher.keys.SCPRFCK, set, h(w)),
	}
}

func (searcher *Searcher) GenSearchTkn(set string, w []byte, preSearchResult *abe.FAMECipher) (*SearchToken, error) {
	tW := searcher.scPRF.EvalCK(searcher.keys.SCPRFCK, set, h(w))
	hexRawStCC, err := searcher.aBE.Decrypt(preSearchResult, searcher.keys.ABEAttrK, searcher.keys.ABEPK)
	rawStCC, err := hex.DecodeString(hexRawStCC)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if rawStCC == nil {
		return nil, nil
	}
	stC := rawStCC[:32]
	c := binary.BigEndian.Uint64(rawStCC[32:])

	return &SearchToken{
		TW:  tW,
		StC: stC,
		C:   c,
	}, nil
}
