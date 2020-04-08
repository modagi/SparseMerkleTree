package sparsemerkletree

import (
	"bytes"
	"math/big"

	"golang.org/x/crypto/sha3"
)

type hash [32]byte

type DB struct {
	Reads  uint
	Writes uint
	kv     map[hash][]byte
}

var (
	Zerohashes []hash
	tt256m1    *big.Int
)

func ByteSliceToHash(in []byte) (result hash) {
	copy(result[:], in[:32])
	return
}

func Keccak256(data []byte) hash {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var result hash
	copy(result[:], h.Sum(nil))

	return result
}

func NewDB() *DB {
	db := new(DB)
	db.kv = make(map[hash][]byte)
	Zerohashes = make([]hash, 257)

	copy(Zerohashes[256][:], bytes.Repeat([]byte{0x00}, 32))
	for i := 256; i > 0; i-- {
		value := append(Zerohashes[i][:], Zerohashes[i][:]...)
		newKey := Keccak256(value)
		Zerohashes[i-1] = newKey
		db.Put(newKey, value)
	}
	tt256m1 = new(big.Int).Sub(new(big.Int).Exp(new(big.Int).SetUint64(2), new(big.Int).SetUint64(256), nil), new(big.Int).SetUint64(1))

	return db
}

func (db *DB) Get(key interface{}) (value []byte) {
	db.Reads += 1
	var k hash
	switch n := (key).(type) {
	case hash:
		k = n
	case []byte:
		k = ByteSliceToHash(n)
	}
	value, _ = db.kv[k]
	return
}

func (db *DB) Put(key hash, value []byte) {
	db.Writes += 1
	db.kv[key] = value
}

func (db *DB) Delete(key hash) {
	delete(db.kv, key)
}
