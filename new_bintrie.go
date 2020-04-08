package sparsemerkletree

import (
	"bytes"
	"math/big"
)

func NewTree(db *DB) hash {
	return Zerohashes[0]
}

func KeyToPath(key hash) (result *big.Int) {
	result = new(big.Int)
	for _, c := range key[:] {
		result.Add(result.Lsh(result, 8), big.NewInt(int64(c)))
	}
	return result
}

func Get(db *DB, root, key hash) []byte {
	v := root[:]
	path := KeyToPath(key)
	for i := 0; i < 256; i++ {
		if new(big.Int).And(new(big.Int).Rsh(path, 255), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			v = db.Get(v)[32:]
		} else {
			v = db.Get(v)[:32]
		}
		path.Lsh(path, 1)
	}
	return v
}

func Update(db *DB, root, key hash, value []byte) []byte {
	v := root[:]
	path := KeyToPath(key)
	path2 := new(big.Int).Set(path)
	var sidenodes []hash
	for i := 0; i < 256; i++ {
		if new(big.Int).And(new(big.Int).Rsh(path, 255), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			sidenodes = append(sidenodes, ByteSliceToHash(db.Get(v)[:32]))
			v = db.Get(v)[32:]
		} else {
			sidenodes = append(sidenodes, ByteSliceToHash(db.Get(v)[32:]))
			v = db.Get(v)[:32]
		}
		path.Lsh(path, 1)
	}
	v = value
	var newv hash
	for i := 0; i < 256; i++ {
		if new(big.Int).And(new(big.Int).Set(path2), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			newvv := append(sidenodes[len(sidenodes)-1][:], v...)
			newv = Keccak256(newvv)
			db.Put(newv, newvv)
		} else {
			newvv := append(v, sidenodes[len(sidenodes)-1][:]...)
			newv = Keccak256(newvv)
			db.Put(newv, newvv)
		}
		path2.Rsh(path2, 1)
		v = newv[:]
		sidenodes = sidenodes[:len(sidenodes)-1]
	}
	return v
}

func MakeMerkleProof(db *DB, root, key hash) []hash {
	v := root
	path := KeyToPath(key)
	var sidenodes []hash

	for i := 0; i < 256; i++ {
		if new(big.Int).And(new(big.Int).Set(new(big.Int).Set(path).Rsh(path, 255)), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			sidenodes = append(sidenodes, ByteSliceToHash(db.Get(v)[:32]))
			v = ByteSliceToHash(db.Get(v)[32:])
		} else {
			sidenodes = append(sidenodes, ByteSliceToHash(db.Get(v)[32:]))
			v = ByteSliceToHash(db.Get(v)[:32])
		}
		path.Lsh(path, 1)
	}
	return sidenodes
}

func VerifyProof(proof []hash, root, key hash, value []byte) bool {
	path := KeyToPath(key)
	v := value
	var newv hash
	for i := 0; i < 256; i++ {
		if new(big.Int).And(new(big.Int).Set(path), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			newv = Keccak256(append(proof[len(proof)-1-i][:], v...))
		} else {
			newv = Keccak256(append(v, proof[len(proof)-1-i][:]...))
		}
		path.Rsh(path, 1)
		v = newv[:]
	}
	return bytes.Equal(root[:], v)
}

func CompressProof(proof []hash) []byte {
	bits := bytes.Repeat([]byte{0x00}, 32)
	var oproof []byte
	for i, p := range proof {
		if p == Zerohashes[i+1] {
			bits[uint(i/8)] ^= (1 << (i % 8))
		} else {
			oproof = append(oproof, p[:]...)
		}
	}
	return append(bits, oproof...)
}

func DecompressProof(oproof []byte) (proof []hash) {
	bits := oproof[:32]
	pos := 32
	for i := 0; i < 256; i++ {
		if bits[uint(i/8)]&(1<<(i%8)) != 0 {
			proof = append(proof, Zerohashes[i+1])
		} else {
			proof = append(proof, ByteSliceToHash(oproof[pos:pos+32]))
			pos += 32
		}
	}
	return proof
}
