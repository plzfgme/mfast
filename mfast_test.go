package mfast_test

import (
	"testing"

	"github.com/plzfgme/mfast"
)

func TestMFAST(t *testing.T) {
	setList := []string{"APart", "BPart", "CPart", "DPart"}
	owner, err := mfast.NewOwner(&mfast.OwnerConfig{
		StorePath: "tmp/owner",
		SetList:   setList,
	})
	if err != nil {
		t.Error(err)
	}
	dKeys, err := owner.DelegateKeys("CPart")
	if err != nil {
		t.Error(err)
	}
	server, err := mfast.NewServer(&mfast.ServerConfig{
		StorePath: "tmp/server",
	})
	searcher := mfast.NewSearcher(&mfast.SearcherConfig{
		SetList: setList,
		Keys:    dKeys,
	})
	updTkn, err := owner.GenUpdateTkn("101", "CPart", []byte("hello"), "add")
	if err != nil {
		t.Error(err)
	}
	err = server.Update(updTkn)
	if err != nil {
		t.Error(err)
	}
	updTkn, err = owner.GenUpdateTkn("131", "CPart", []byte("gyt"), "add")
	if err != nil {
		t.Error(err)
	}
	err = server.Update(updTkn)
	if err != nil {
		t.Error(err)
	}
	psrhTkn := searcher.GenPreSearchTkn("CPart", []byte("gyt"))
	psrhRes, err := server.PreSearch(psrhTkn)
	if err != nil {
		t.Error(err)
	}
	srhTkn, err := searcher.GenSearchTkn("CPart", []byte("gyt"), psrhRes)
	if err != nil {
		t.Error(err)
	}
	srhRes, err := server.Search(srhTkn)
	if err != nil {
		t.Error(err)
	}
	t.Log(srhRes)
}
