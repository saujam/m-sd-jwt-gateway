package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Node struct {
	Hash  string
	Left  *Node
	Right *Node
}

type Tree struct {
	Root   *Node
	Leaves []string
}

func NewTree(attributes []string) *Tree {
	leaves := make([]string, len(attributes))
	for i, attr := range attributes {
		salt := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d%s", i, attr))))
		saltedHash := sha256.Sum256([]byte(salt + attr))
		leaves[i] = hex.EncodeToString(saltedHash[:])
	}
	t := &Tree{Leaves: leaves}
	t.Root = t.build(0, len(leaves)-1)
	return t
}

func (t *Tree) build(start, end int) *Node {
	if start == end {
		return &Node{Hash: t.Leaves[start]}
	}
	mid := (start + end) / 2
	left := t.build(start, mid)
	right := t.build(mid+1, end)
	combined := left.Hash + right.Hash
	hash := sha256.Sum256([]byte(combined))
	return &Node{
		Hash:  hex.EncodeToString(hash[:]),
		Left:  left,
		Right: right,
	}
}

func (t *Tree) RootHash() string {
	return t.Root.Hash
}

// GetProof returns the Merkle authentication path for a range of leaves (page)
func (t *Tree) GetProof(start, size int) []string {
	if start < 0 || start+size > len(t.Leaves) {
		return nil
	}
	proof := make([]string, 0, 20) // log N is small
	t.collectProof(t.Root, 0, len(t.Leaves)-1, start, start+size-1, &proof)
	return proof
}

func (t *Tree) collectProof(node *Node, nodeStart, nodeEnd, queryStart, queryEnd int, proof *[]string) {
	if nodeStart > queryEnd || nodeEnd < queryStart {
		return
	}
	if nodeStart >= queryStart && nodeEnd <= queryEnd {
		return // fully covered
	}
	mid := (nodeStart + nodeEnd) / 2
	if node.Left != nil {
		t.collectProof(node.Left, nodeStart, mid, queryStart, queryEnd, proof)
	}
	if node.Right != nil {
		t.collectProof(node.Right, mid+1, nodeEnd, queryStart, queryEnd, proof)
	}
	// Add sibling hash to proof path
	if node.Left != nil && node.Right != nil {
		if mid < queryStart {
			*proof = append(*proof, node.Left.Hash)
		} else if mid >= queryEnd {
			*proof = append(*proof, node.Right.Hash)
		}
	}
}