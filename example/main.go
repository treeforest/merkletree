package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/treeforest/merkletree"
)

func getFakeTxHashes() [][]byte {
	fakeTxHashes := make([][]byte, 0)
	for i := 0; i < 15; i++ {
		fakeTx := make([]byte, 128)
		_, _ = rand.Read(fakeTx)
		fakeTxHash := sha256.Sum256(fakeTx)
		fakeTxHashes = append(fakeTxHashes, fakeTxHash[:])
	}
	return fakeTxHashes
}

func main() {
	fakeTxHashes := getFakeTxHashes()

	tree := merkletree.New()

	// build merkle tree by txHashes
	tree.Build(fakeTxHashes)

	// generate merkle proof with txHash
	txHash := fakeTxHashes[2]
	proof, _ := tree.GenMerkleProof(txHash)

	// verify txHash with proof ans merkleRoot
	ok := merkletree.Verify(txHash, proof, tree.Root())
	fmt.Println("verify status: ", ok)
}
