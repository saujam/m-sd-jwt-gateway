package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
)

// Node represents a single node in the Merkle tree.
type Node struct {
	Hash  string
	Left  *Node
	Right *Node
}

// Tree is a binary Merkle tree built over a slice of string attributes.
type Tree struct {
	Root   *Node
	Leaves []*Node
}

// hash256 returns the hex-encoded SHA-256 hash of the input string.
func hash256(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// hashPair combines two child hashes into a parent hash.
func hashPair(left, right string) string {
	return hash256(left + right)
}

// NewTree builds a Merkle tree from a slice of string attributes.
// If the number of leaves is odd, the last leaf is duplicated (standard practice).
func NewTree(attributes []string) *Tree {
	if len(attributes) == 0 {
		return &Tree{Root: &Node{Hash: hash256("")}}
	}

	leaves := make([]*Node, len(attributes))
	for i, attr := range attributes {
		leaves[i] = &Node{Hash: hash256(attr)}
	}

	t := &Tree{Leaves: leaves}
	t.Root = t.buildTree(leaves)
	return t
}

// buildTree recursively combines a layer of nodes into their parents.
func (t *Tree) buildTree(nodes []*Node) *Node {
	if len(nodes) == 1 {
		return nodes[0]
	}

	// Duplicate last node if odd count.
	if len(nodes)%2 != 0 {
		nodes = append(nodes, nodes[len(nodes)-1])
	}

	var parents []*Node
	for i := 0; i < len(nodes); i += 2 {
		parent := &Node{
			Hash:  hashPair(nodes[i].Hash, nodes[i+1].Hash),
			Left:  nodes[i],
			Right: nodes[i+1],
		}
		parents = append(parents, parent)
	}
	return t.buildTree(parents)
}

// RootHash returns the hex-encoded SHA-256 root hash of the tree.
func (t *Tree) RootHash() string {
	if t.Root == nil {
		return ""
	}
	return t.Root.Hash
}

// Depth returns the number of levels in the tree including the root.
// main.go calls tree.Depth() — this method was missing before.
func (t *Tree) Depth() int {
	if len(t.Leaves) == 0 {
		return 0
	}
	return int(math.Ceil(math.Log2(float64(len(t.Leaves))))) + 1
}

// ProofElement is one sibling hash in the Merkle authentication path.
type ProofElement struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// GetProof returns the Merkle authentication path for the page attributes[start:end].
// Bounds are checked — will not panic on out-of-range inputs.
func (t *Tree) GetProof(start, end int) []ProofElement {
	if len(t.Leaves) == 0 || start >= len(t.Leaves) || start >= end {
		return []ProofElement{}
	}
	if end > len(t.Leaves) {
		end = len(t.Leaves)
	}
	// Return the authentication path for the first leaf in the requested range.
	return t.proofForLeaf(start)
}

// proofForLeaf returns the sibling path from leaf[index] up to the root.
func (t *Tree) proofForLeaf(index int) []ProofElement {
	if index >= len(t.Leaves) {
		return nil
	}

	var proof []ProofElement
	nodes := make([]*Node, len(t.Leaves))
	copy(nodes, t.Leaves)
	i := index

	for len(nodes) > 1 {
		// Duplicate last node if the layer has an odd count.
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}

		if i%2 == 0 {
			// Current node is a left child — sibling is to the right.
			if i+1 < len(nodes) {
				proof = append(proof, ProofElement{
					Hash:     nodes[i+1].Hash,
					Position: "right",
				})
			}
		} else {
			// Current node is a right child — sibling is to the left.
			proof = append(proof, ProofElement{
				Hash:     nodes[i-1].Hash,
				Position: "left",
			})
		}

		// Build the next layer up.
		var parents []*Node
		for j := 0; j < len(nodes); j += 2 {
			parents = append(parents, &Node{
				Hash: hashPair(nodes[j].Hash, nodes[j+1].Hash),
			})
		}
		nodes = parents
		i = i / 2
	}

	return proof
}