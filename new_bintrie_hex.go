package sparsemerkletree

import (
	"bytes"
	"math/big"
	"reflect"
)

// Create a new empty tree
func T3NewTree(db *DB) hash {
	return Zerohashes[0]
}

// Convert a binary key into an integer path value
func T3KeyToPath(key interface{}) (result *big.Int) {
	result = new(big.Int)
	var k []byte
	switch n := (key).(type) {
	case hash:
		k = n[:]
	case []byte:
		k = n
	}
	for _, c := range k {
		result.Add(result.Lsh(result, 8), big.NewInt(int64(c)))
	}
	return result
}

// And convert back
func T3PathToKey(path *big.Int) []byte {
	tmp := new(big.Int).And(new(big.Int).Set(path), tt256m1).Bytes()
	if len(tmp) != 32 {
		for len(tmp) < 32 {
			tmp = append([]byte("\x00"), tmp...)
		}
	}
	return tmp
}

// Read a key from a given tree
func T3Get(db *DB, root, key hash) []byte {
	v := root[:]
	path := T3KeyToPath(key)
	for i := 0; i < 256; i += 4 {
		if bytes.Equal(v, Zerohashes[i][:]) {
			return bytes.Repeat([]byte{0x00}, 32)
		}
		child := db.Get(v)
		if len(child) == 65 {
			if new(big.Int).Mod(new(big.Int).Set(path), new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)).Cmp(KeyToPath(ByteSliceToHash(child[1:33]))) == 0 {
				return child[33:]
			} else {
				return bytes.Repeat([]byte{0x00}, 32)
			}
		} else {
			index := new(big.Int).And(new(big.Int).Rsh(path, 252), big.NewInt(15))
			v = child[32*index.Uint64() : 32*index.Uint64()+32]
		}
		path.Lsh(path, 4)
	}
	return v
}

// Make a root hash of a (sub)tree with a single key/value pair
func T3MakeSingleKeyHash(path *big.Int, depth uint32, value []byte) []byte {
	if depth == 256 {
		return value
	} else if new(big.Int).And(new(big.Int).Rsh(path, 255), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
		tmp := Keccak256(append(Zerohashes[depth+1][:], T3MakeSingleKeyHash(new(big.Int).Set(path).Lsh(path, 1), depth+1, value)...))
		return tmp[:]
	} else {
		tmp := Keccak256(append(T3MakeSingleKeyHash(new(big.Int).Lsh(path, 1), depth+1, value), Zerohashes[depth+1][:]...))
		return tmp[:]
	}
}

// Hash together 16 elements
func T3Hash16Els(vals []hash) hash {
	if len(vals) != 16 {
		panic("T3Hash16Els wrong els length")
	}
	tmp, tmp2 := make([]hash, 16), make([]hash, 0, 16)
	copy(tmp[:], vals[:])
	for i := 0; i < 4; i++ {
		for j := 0; j < len(tmp); j += 2 {
			tmp2 = append(tmp2, Keccak256(append(tmp[j][:], tmp[j+1][:]...)))
		}
		tmp = []hash{}
		tmp, tmp2 = tmp2[:], tmp[:]
	}
	return tmp[0]
}

func T3MakeZeroHashes(depth uint32) (result []hash) {
	for i := 0; i < 16; i++ {
		result = append(result, Zerohashes[depth])
	}
	return
}

func T3FlattenChildren(children []hash) (result []byte) {
	for i := 0; i < 16; i++ {
		result = append(result, children[i][:]...)
	}
	return
}

// Make a root hash of a (sub)tree with two key/value pairs, and save intermediate nodes in the DB
func T3MakeDoubleKeyHash(db *DB, path1, path2 *big.Int, depth uint32, value1, value2 []byte) hash {
	if depth == 256 {
		panic("Cannot fit two values into one slot!")
	}
	var children []hash
	path1Index := new(big.Int).And(new(big.Int).Rsh(path1, 252), big.NewInt(15))
	path2Index := new(big.Int).And(new(big.Int).Rsh(path2, 252), big.NewInt(15))
	if path1Index.Cmp(path2Index) == 0 {
		children = T3MakeZeroHashes(depth + 4)
		tmp := T3MakeDoubleKeyHash(db, new(big.Int).Lsh(path1, 4), new(big.Int).Lsh(path2, 4), depth+4, value1, value2)
		children[path1Index.Uint64()] = tmp
	} else {
		L := T3MakeSingleKeyHash(new(big.Int).Lsh(path1, 4), depth+4, value1)
		R := T3MakeSingleKeyHash(new(big.Int).Lsh(path2, 4), depth+4, value2)
		db.Put(ByteSliceToHash(L), append([]byte("\x01"), append(T3PathToKey(new(big.Int).Lsh(path1, 4)), value1...)...))
		db.Put(ByteSliceToHash(R), append([]byte("\x01"), append(T3PathToKey(new(big.Int).Lsh(path2, 4)), value2...)...))
		children = T3MakeZeroHashes(depth + 4)
		children[path1Index.Uint64()] = ByteSliceToHash(L)
		children[path2Index.Uint64()] = ByteSliceToHash(R)
	}
	h := T3Hash16Els(children)
	db.Put(h, T3FlattenChildren(children))
	return h
}

// Update a tree with a given key/value pair
func T3Update(db *DB, root, key hash, value []byte) []byte {
	tmp := T3update(db, root, T3KeyToPath(key), 0, value)
	return tmp
}

func T3update(db *DB, root hash, path *big.Int, depth uint32, value []byte) []byte {
	if depth == 256 {
		return value
	}
	// Update an empty subtree: make a single-key subtree
	if reflect.DeepEqual(root, Zerohashes[depth]) {
		k := T3MakeSingleKeyHash(path, depth, value)
		db.Put(ByteSliceToHash(k), append([]byte("\x01"), append(T3PathToKey(path), value...)...))
		return k
	}
	child := db.Get(root)
	if len(child) == 65 {
		// Update a single-key subtree: make a double-key subtree
		origpath := T3KeyToPath(child[1:33])
		origvalue := child[33:]
		tmp := T3MakeDoubleKeyHash(db, path, origpath, depth, value, origvalue)

		return tmp[:]
	} else {
		// Update a multi-key subtree: recurse down
		if len(child) != 512 {
			panic("T3update wrong children length")
		}
		index := new(big.Int).And(new(big.Int).Rsh(path, 252), big.NewInt(15)).Uint64()
		newValue := T3update(db, ByteSliceToHash(child[index*32:index*32+32]), new(big.Int).Lsh(path, 4), depth+4, value)
		copy(child[32*index:32*index+32], newValue)
		var newChildren []hash
		for i := 0; i < 16; i++ {
			newChildren = append(newChildren, ByteSliceToHash(child[32*i:32*i+32]))
		}
		h := T3Hash16Els(newChildren)
		db.Put(h, child)
		return h[:]
	}
}
