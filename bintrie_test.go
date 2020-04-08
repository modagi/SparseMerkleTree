package sparsemerkletree

import (
	"encoding/hex"
	"fmt"
	"testing"
)

var (
	keys []hash
)

func init() {
	for i := 0; i < 1000; i++ {
		keys = append(keys, Keccak256([]byte{byte(uint32(i / 256)), byte(i % 256)}))
	}
}

func TestTrie1(t *testing.T) {
	db := NewDB()
	root := NewTree(db)
	tree := root[:]

	for _, k := range keys {
		tree = Update(db, ByteSliceToHash(tree), k, k[:])
	}

	fmt.Printf("Root: %s", hex.EncodeToString(tree))
}

func TestTrie2(t *testing.T) {
	db := NewDB()
	root := T2NewTree(db)
	tree := root[:]

	for _, k := range keys {
		tree = T2Update(db, ByteSliceToHash(tree), k, k[:])
	}

	fmt.Printf("Root: %s", hex.EncodeToString(tree))
}

func TestTrie3(t *testing.T) {
	db := NewDB()
	root := T3NewTree(db)
	tree := root[:]

	for _, k := range keys {
		tree = T3Update(db, ByteSliceToHash(tree), k, k[:])
	}

	fmt.Printf("Root: %s", hex.EncodeToString(tree))
}
