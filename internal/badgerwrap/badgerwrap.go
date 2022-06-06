package badgerwrap

import (
	badger "github.com/dgraph-io/badger/v3"
)

type WrappedDB struct {
	db *badger.DB
}

type KVPair interface {
	GetKey() []byte
	GetVal() []byte
}

func Open(path string) (*WrappedDB, error) {
	config := badger.DefaultOptions(path)
	config.Logger = nil
	db, err := badger.Open(config)
	if err != nil {
		return nil, err
	}
	return &WrappedDB{
		db,
	}, nil
}

func (wrap *WrappedDB) Get(key []byte) ([]byte, error) {
	var ret []byte
	err := wrap.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			if err == badger.ErrKeyNotFound {
				ret = nil
				return nil
			}
			return err
		}
		err = item.Value(func(val []byte) error {
			ret = val
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})

	return ret, err
}

func (wrap *WrappedDB) Set(key, val []byte) error {
	return wrap.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, val)
	})
}

func (wrap *WrappedDB) MultiSet(pairs []KVPair) error {
	return wrap.db.Update(func(txn *badger.Txn) error {
		for _, pair := range pairs {
			err := txn.Set(pair.GetKey(), pair.GetVal())
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (wrap *WrappedDB) Del(key []byte) error {
	return wrap.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

func (wrap *WrappedDB) MultiDel(pairs []KVPair) error {
	return wrap.db.Update(func(txn *badger.Txn) error {
		for _, pair := range pairs {
			err := txn.Delete(pair.GetKey())
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (wrap *WrappedDB) Close() error {
	return wrap.db.Close()
}
