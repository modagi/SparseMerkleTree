package sparsemerkletree

import (
	"bytes"
	"math/big"
	"reflect"
)

// Create a new empty tree
func T2NewTree(db *DB) hash {
	return Zerohashes[0]
}

// Convert a binary key into an integer path value
func T2KeyToPath(key interface{}) (result *big.Int) {
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
func T2PathToKey(path *big.Int) []byte {
	tmp := new(big.Int).And(new(big.Int).Set(path), tt256m1).Bytes()
	if len(tmp) != 32 {
		for len(tmp) < 32 {
			tmp = append([]byte("\x00"), tmp...)
		}
	}
	return tmp
}

// Read a key from a given tree
func T2Get(db *DB, root, key hash) []byte {
	v := root[:]
	path := T2KeyToPath(key)
	for i := 0; i < 256; i++ {
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
			if new(big.Int).And(new(big.Int).Rsh(path, 255), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
				v = child[32:]
			} else {
				v = child[:32]
			}
		}
		path.Lsh(path, 1)
	}
	return v
}

// Make a root hash of a (sub)tree with a single key/value pair
func T2MakeSingleKeyHash(path *big.Int, depth uint32, value []byte) []byte {
	if depth == 256 {
		return value
	} else if new(big.Int).And(new(big.Int).Rsh(path, 255), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
		tmp := Keccak256(append(Zerohashes[depth+1][:], T2MakeSingleKeyHash(new(big.Int).Set(path).Lsh(path, 1), depth+1, value)...))
		return tmp[:]
	} else {
		tmp := Keccak256(append(T2MakeSingleKeyHash(new(big.Int).Set(path).Lsh(path, 1), depth+1, value), Zerohashes[depth+1][:]...))
		return tmp[:]
	}
}

// Make a root hash of a (sub)tree with two key/value pairs, and save intermediate nodes in the DB
func T2MakeDoubleKeyHash(db *DB, path1, path2 *big.Int, depth uint32, value1, value2 []byte) []byte {
	if depth == 256 {
		panic("Cannot fit two values into one slot!")
	}
	var child []byte
	if new(big.Int).And(new(big.Int).Rsh(path1, 255), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
		if new(big.Int).And(new(big.Int).Rsh(path2, 255), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			tmp := T2MakeDoubleKeyHash(db, new(big.Int).Set(path1).Lsh(path1, 1), new(big.Int).Set(path2).Lsh(path2, 1), depth+1, value1, value2)
			child = append(Zerohashes[depth+1][:], tmp...)
			childHash := Keccak256(child)
			db.Put(childHash, child)

			return childHash[:]
		} else {
			L := T2MakeSingleKeyHash(new(big.Int).Set(path2).Lsh(path2, 1), depth+1, value2)
			R := T2MakeSingleKeyHash(new(big.Int).Set(path1).Lsh(path1, 1), depth+1, value1)
			db.Put(ByteSliceToHash(L), append([]byte("\x01"), append(T2PathToKey(new(big.Int).Set(path2).Lsh(path2, 1)), value2...)...))
			db.Put(ByteSliceToHash(R), append([]byte("\x01"), append(T2PathToKey(new(big.Int).Set(path1).Lsh(path1, 1)), value1...)...))
			child = append(L[:], R[:]...)
		}
	} else {
		if new(big.Int).And(new(big.Int).Rsh(path2, 255), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			L := T2MakeSingleKeyHash(new(big.Int).Set(path1).Lsh(path1, 1), depth+1, value1)
			R := T2MakeSingleKeyHash(new(big.Int).Set(path2).Lsh(path2, 1), depth+1, value2)
			db.Put(ByteSliceToHash(L), append([]byte("\x01"), append(T2PathToKey(new(big.Int).Set(path1).Lsh(path1, 1)), value1...)...))
			db.Put(ByteSliceToHash(R), append([]byte("\x01"), append(T2PathToKey(new(big.Int).Set(path2).Lsh(path2, 1)), value2...)...))
			child = append(L[:], R[:]...)
		} else {
			tmp := T2MakeDoubleKeyHash(db, new(big.Int).Lsh(path1, 1), new(big.Int).Lsh(path2, 1), depth+1, value1, value2)
			child = append(tmp, Zerohashes[depth+1][:]...)
		}
	}
	childHash := Keccak256(child)
	db.Put(childHash, child)
	return childHash[:]
}

// Update a tree with a given key/value pair
func T2Update(db *DB, root, key hash, value []byte) []byte {
	return T2update(db, root, T2KeyToPath(key), 0, value)
}

func T2update(db *DB, root hash, path *big.Int, depth uint32, value []byte) []byte {
	if depth == 256 {
		return value
	}
	// Update an empty subtree: make a single-key subtree
	if reflect.DeepEqual(root, Zerohashes[depth]) {
		k := T2MakeSingleKeyHash(path, depth, value)
		db.Put(ByteSliceToHash(k), append([]byte("\x01"), append(T2PathToKey(path), value...)...))
		return k
	}
	child := db.Get(root)
	if len(child) == 65 {
		// Update a single-key subtree: make a double-key subtree
		origpath := T2KeyToPath(child[1:33])
		origvalue := child[33:]
		tmp := T2MakeDoubleKeyHash(db, path, origpath, depth, value, origvalue)

		return tmp
	} else if new(big.Int).And(new(big.Int).Rsh(path, 255), big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
		// Update a multi-key subtree: recurse down
		newChild := append(child[:32], T2update(db, ByteSliceToHash(child[32:]), new(big.Int).Lsh(path, 1), depth+1, value)...)
		k := Keccak256(newChild)
		db.Put(k, newChild)
		return k[:]
	} else {
		newChild := append(T2update(db, ByteSliceToHash(child[:32]), new(big.Int).Lsh(path, 1), depth+1, value), child[32:]...)
		k := Keccak256(newChild)
		db.Put(k, newChild)
		return k[:]
	}
}
