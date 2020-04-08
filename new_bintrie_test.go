package sparsemerkletree

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"testing"
)

var (
	zeroroothash = []byte("\xa7\xff\x9e\x28\xff\xd3\xde\xf4\x43\xd3\x24\x54\x76\x88\xc2\xc4\xeb\x98\xed\xf7\xda\x75\x7d\x6b\xfa\x22\xbf\xf5\x5b\x9c\xe2\x4a")
)

func TestKeccak256(t *testing.T) {
	exp := []byte("\xc5\xd2\x46\x01\x86\xf7\x23\x3c\x92\x7e\x7d\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6\x53\xca\x82\x27\x3b\x7b\xfa\xd8\x04\x5d\x85\xa4\x70")
	result := Keccak256([]byte{})
	if !bytes.Equal(result[:], exp) {
		t.Errorf("expected %x got %x", exp, result)
	}
}

func TestEmptyTrie(t *testing.T) {
	NewDB()
	if len(Zerohashes) != 257 {
		t.Errorf("expected 257 got %d", len(Zerohashes))
	}
	if !bytes.Equal(Zerohashes[0][:], zeroroothash) {
		t.Errorf("expected %x got %x", zeroroothash, Zerohashes[0])
	}
}

func TestBinTrie(t *testing.T) {
	db := NewDB()
	root := NewTree(db)
	tree := root[:]

	keyCount := 10
	for i := 0; i < keyCount; i++ {
		value := Keccak256([]byte(strconv.Itoa(i * i * i)))
		tree = Update(db, ByteSliceToHash(tree), Keccak256([]byte(strconv.Itoa(i))), value[:])
	}
	fmt.Printf("%d elements added\n", keyCount)
	for i := 0; i < keyCount; i++ {
		v := Get(db, ByteSliceToHash(tree), Keccak256([]byte(strconv.Itoa(i))))
		value := Keccak256([]byte(strconv.Itoa(i * i * i)))
		if !bytes.Equal(v, value[:]) {
			t.Errorf("expected %x got %x", value[:], v)
		}
	}
	fmt.Printf("Get requests for present elements successful\n")
	for i := keyCount + 1; i < keyCount*2; i++ {
		v := Get(db, ByteSliceToHash(tree), Keccak256([]byte(strconv.Itoa(i))))
		value := bytes.Repeat([]byte{0x00}, 32)
		if !bytes.Equal(v, value[:]) {
			t.Errorf("expected %x got %x", value[:], v)
		}
	}
	fmt.Printf("Get requests for absent elements successful\n")

	tl := 0
	for i := 0; i < keyCount*2; i++ {
		key := Keccak256([]byte(strconv.Itoa(i)))
		var value hash
		if i < keyCount {
			value = Keccak256([]byte(strconv.Itoa(i * i * i)))
		} else {
			value = ByteSliceToHash(bytes.Repeat([]byte{0x00}, 32))
		}
		proof := MakeMerkleProof(db, ByteSliceToHash(tree), key)
		if !VerifyProof(proof, ByteSliceToHash(tree), key, value[:]) {
			t.Errorf("Failed to verify proof")
		}
		if !reflect.DeepEqual(DecompressProof(CompressProof(proof)), proof) {
			t.Errorf("Failed to compress/decompress")
		}
		tl += len(CompressProof(proof))
	}
	fmt.Printf("Average total length at %d keys: %d, %d including key\n", keyCount, uint((tl/keyCount)/2), uint((tl/keyCount)/2+32))
}
