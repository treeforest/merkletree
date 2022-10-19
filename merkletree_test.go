package merkletree

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewMerkleTree(t *testing.T) {
	txHashes := make([][]byte, 0)
	for i := 0; i < 10; i++ {
		b := make([]byte, 64)
		_, _ = rand.Read(b)
		h := sha256.Sum256(b)
		txHashes = append(txHashes, h[:])
	}

	tree := New()
	tree.Build(txHashes)

	txHash := txHashes[2]
	proof, err := tree.GenMerkleProof(txHash)
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		txHash = txHashes[i]
		if i == 2 {
			require.Equal(t, true, Verify(txHash, proof, tree.Root()))
		} else {
			require.Equal(t, false, Verify(txHash, proof, tree.Root()))
		}
	}
}
