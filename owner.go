package mfast

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fentec-project/gofe/abe"
	"github.com/lukechampine/fastxor"
	"github.com/plzfgme/mfast/internal/badgerwrap"
	"github.com/plzfgme/mfast/internal/scprf"
)

type ownerKeys struct {
	SCPRFK []byte
	ABEPK  *abe.FAMEPubKey
	ABESK  *abe.FAMESecKey
}

type Owner struct {
	db      *badgerwrap.WrappedDB
	scPRF   *scprf.SCPRF
	aBE     *abe.FAME
	keys    *ownerKeys
	setList []string
}

const OwnerKeyLength = 32

var OwnerKeyLengthError = fmt.Errorf("mfast: Key length should be %v", OwnerKeyLength)

var NoKeyError = fmt.Errorf("mfast: No Key")

type UpdateState struct {
	key []byte
	val []byte
}

func (st *UpdateState) GetKey() []byte {
	return st.key
}

func (st *UpdateState) GetVal() []byte {
	return st.val
}

type OwnerConfig struct {
	StorePath string
	SetList   []string
}

var NonDirFileError = fmt.Errorf("mfast: store path exists and is not a directory.")

func NewOwner(config *OwnerConfig) (*Owner, error) {
	if stat, err := os.Stat(config.StorePath); os.IsNotExist(err) {
		err := os.MkdirAll(config.StorePath, 0755)
		if err != nil {
			return nil, err
		}
	} else if !stat.IsDir() {
		return nil, NonDirFileError
	}
	db, err := badgerwrap.Open(filepath.Join(config.StorePath, "localmap.db"))
	if err != nil {
		return nil, err
	}
	abeCipher := abe.NewFAME()

	keys := &ownerKeys{}
	keysPath := filepath.Join(config.StorePath, "keys")
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		keys.SCPRFK = make([]byte, 32)
		rand.Read(keys.SCPRFK)
		keys.ABEPK, keys.ABESK, err = abeCipher.GenerateMasterKeys()
		if err != nil {
			return nil, err
		}
		jsonKeys, err := json.Marshal(keys)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(keysPath, jsonKeys, 0600)
		if err != nil {
			return nil, err
		}
	} else {
		jsonKeys, err := os.ReadFile(keysPath)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(jsonKeys, keys)
		if err != nil {
			return nil, err
		}
	}

	return &Owner{
		db:      db,
		keys:    keys,
		scPRF:   scprf.NewSCPRF(config.SetList),
		aBE:     abeCipher,
		setList: config.SetList,
	}, nil
}

func (owner *Owner) GenUpdateTkn(id string, set string, w []byte, op string) (*UpdateToken, error) {
	bytesId := []byte(id)
	tW := owner.scPRF.EvalMK(owner.keys.SCPRFK, set, h([]byte(set+":"+string(w))))
	rawStCC, err := owner.db.Get(w)
	if err != nil {
		return nil, err
	}
	var stC []byte
	var c uint64
	if rawStCC != nil {
		stC = rawStCC[:32]
		c = binary.BigEndian.Uint64(rawStCC[32:])
	} else {
		stC = make([]byte, 32)
		_, err := rand.Read(stC)
		if err != nil {
			return nil, err
		}
		c = 0
	}
	kCPlus1 := make([]byte, 32)
	_, err = rand.Read(kCPlus1)
	if err != nil {
		return nil, err
	}
	stCPlus1 := p(kCPlus1, stC)
	bytesCPlus1 := make([]byte, 8)
	binary.BigEndian.PutUint64(bytesCPlus1, c+1)
	newMapV := append(stCPlus1, bytesCPlus1...)
	owner.db.Set(w, newMapV)
	bytesOP := make([]byte, 1)
	if op == "add" {
		bytesOP[0] = byte(0)
	} else {
		bytesOP[0] = byte(1)
	}
	ePart1 := append(append(bytesOP, kCPlus1...), bytesId...)
	ePart2 := h2(append(tW, stCPlus1...))
	for len(ePart2) < len(ePart1) {
		ePart2 = append(ePart2, ePart2[:32]...)
	}
	e := make([]byte, len(ePart1))
	fastxor.Bytes(e, ePart1, ePart2)
	u := h1(append(tW, stCPlus1...))

	msp, err := abe.BooleanToMSP(set, false)
	if err != nil {
		return nil, err
	}
	ec, err := owner.aBE.Encrypt(hex.EncodeToString(newMapV), msp, owner.keys.ABEPK)
	if err != nil {
		return nil, err
	}

	return &UpdateToken{
		U:  u,
		E:  e,
		TW: tW,
		EC: ec,
	}, nil
}

func (owner *Owner) GenSearchTkn(set string, w []byte) (*SearchToken, error) {
	tW := owner.scPRF.EvalMK(owner.keys.SCPRFK, set, h([]byte(set+":"+string(w))))
	rawStCC, err := owner.db.Get(w)
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

func (owner *Owner) DelegateKeys(set string) (*DelegatedKeys, error) {
	abeAttrK, err := owner.aBE.GenerateAttribKeys(owner.setList, owner.keys.ABESK)
	if err != nil {
		return nil, err
	}
	return &DelegatedKeys{
		SCPRFCK:  owner.scPRF.Constrain(owner.keys.SCPRFK, set),
		ABEAttrK: abeAttrK,
		ABEPK:    owner.keys.ABEPK,
	}, nil
}

func (owner *Owner) Close() error {
	return owner.db.Close()
}
