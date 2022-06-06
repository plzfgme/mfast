package mfast

import (
	"github.com/fentec-project/gofe/abe"
	"github.com/plzfgme/consprf"
)

type UpdateToken struct {
	U  []byte
	E  []byte
	TW []byte
	EC *abe.FAMECipher
}

type PreSearchToken struct {
	TW []byte
}

type SearchToken struct {
	TW  []byte
	StC []byte
	C   uint64
}

type DelegatedKeys struct {
	SCPRFCK  consprf.GGMConstrainedKey
	ABEAttrK *abe.FAMEAttribKeys
	ABEPK    *abe.FAMEPubKey
}
