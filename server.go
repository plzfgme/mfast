package mfast

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/fentec-project/gofe/abe"
	"github.com/lukechampine/fastxor"
	"github.com/plzfgme/mfast/internal/badgerwrap"
)

type Server struct {
	indexDB *badgerwrap.WrappedDB
	eMapDB  *badgerwrap.WrappedDB
}

type ServerConfig struct {
	StorePath string
}

func NewServer(config *ServerConfig) (*Server, error) {
	if stat, err := os.Stat(config.StorePath); os.IsNotExist(err) {
		err := os.MkdirAll(config.StorePath, 0755)
		if err != nil {
			return nil, err
		}
	} else if !stat.IsDir() {
		return nil, NonDirFileError
	}
	indexDBPath := filepath.Join(config.StorePath, "index.db")
	indexDB, err := badgerwrap.Open(indexDBPath)
	if err != nil {
		return nil, err
	}
	eMapDBPath := filepath.Join(config.StorePath, "emap.db")
	eMapDB, err := badgerwrap.Open(eMapDBPath)
	if err != nil {
		return nil, err
	}

	return &Server{
		indexDB,
		eMapDB,
	}, nil
}

func (server *Server) Update(tkn *UpdateToken) error {
	jsonEC, err := json.Marshal(tkn.EC)
	if err != nil {
		return err
	}
	err = server.indexDB.Set(tkn.U, tkn.E)
	if err != nil {
		return err
	}
	err = server.eMapDB.Set(tkn.TW, jsonEC)
	if err != nil {
		return err
	}
	return nil
}

func (server *Server) PreSearch(tkn *PreSearchToken) (*abe.FAMECipher, error) {
	jsonEC, err := server.eMapDB.Get(tkn.TW)
	if err != nil {
		return nil, err
	}
	if jsonEC == nil {
		return nil, nil
	}
	EC := &abe.FAMECipher{}
	err = json.Unmarshal(jsonEC, EC)
	if err != nil {
		return nil, err
	}
	return EC, nil
}

// TODO error handle
func (server *Server) Search(tkn *SearchToken) ([]string, error) {
	ids := make(map[string]struct{})
	delta := make(map[string]struct{})
	stI := tkn.StC
	for i := tkn.C; i > 0; i-- {
		u := h1(append(tkn.TW, stI...))
		e, err := server.indexDB.Get(u)
		if err != nil {
			return nil, err
		} else if e == nil {
			return nil, nil
		}
		ePart2 := h2(append(tkn.TW, stI...))
		for len(ePart2) < len(e) {
			ePart2 = append(ePart2, ePart2[:32]...)
		}
		ePart1 := make([]byte, len(e))
		fastxor.Bytes(ePart1, e, ePart2)
		bytesOP := int(ePart1[0])
		kI := ePart1[1:33]
		id := ePart1[33:]
		if bytesOP == 1 {
			delta[string(id)] = struct{}{}
		} else {
			_, ok := delta[string(id)]
			if ok {
				delete(delta, string(id))
			} else {
				ids[string(id)] = struct{}{}
			}
		}
		stI = invP(kI, stI)
	}
	keys := make([]string, 0, len(ids))
	for k := range ids {
		keys = append(keys, k)
	}

	return keys, nil
}

// FIXME
func (server *Server) Close() error {
	server.eMapDB.Close()
	return server.indexDB.Close()
}
