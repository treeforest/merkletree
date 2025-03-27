package merkletree

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestMerkleProofWithOrder(t *testing.T) {
	// 构建测试数据
	hashes := [][]byte{
		[]byte("tx1"), []byte("tx2"), []byte("tx3"),
	}

	// 创建Merkle树
	tree := NewMerkleTree(hashes)

	// 生成证明
	proof, err := tree.GenerateProof([]byte("tx1"))
	if err != nil {
		t.Fatal(err)
	}

	// 验证证明
	if !VerifyProof([]byte("tx1"), proof, tree.Root()) {
		t.Fatal("Verification failed")
	}

	// 篡改测试
	fakeProof := &Proof{
		Hashes: [][]byte{[]byte("fake1"), []byte("fake2")},
		IsLeft: []bool{true, false},
	}
	if VerifyProof([]byte("tx1"), fakeProof, tree.Root()) {
		t.Fatal("Fake proof passed")
	}
}

// 生成随机哈希数据
func generateHashes(n int) [][]byte {
	hashes := make([][]byte, n)
	for i := 0; i < n; i++ {
		data := make([]byte, 32)
		_, _ = rand.Read(data)
		hash := sha256.Sum256(data)
		hashes[i] = hash[:]
	}

	return hashes
}

// 测试用例：10万笔交易
func TestMerkleTree_10kTransactions(t *testing.T) {
	const size = 100_000
	hashes := generateHashes(size)

	// 构建树
	tree := NewMerkleTree(hashes)

	// 测试中间节点证明
	t.Run("MiddleNode", func(t *testing.T) {
		proof, err := tree.GenerateProof(hashes[size/2])
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyProof(hashes[size/2], proof, tree.Root()) {
			t.Fatal("Middle node verification failed")
		}
	})

	// 测试末尾节点证明
	t.Run("LastNode", func(t *testing.T) {
		proof, err := tree.GenerateProof(hashes[size-1])
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyProof(hashes[size-1], proof, tree.Root()) {
			t.Fatal("Last node verification failed")
		}
	})

	// 测试恶意证明
	t.Run("InvalidProof", func(t *testing.T) {
		proof, _ := tree.GenerateProof(hashes[0])
		proof.Hashes[0] = []byte("malicious hash") // 篡改证明
		if VerifyProof(hashes[0], proof, tree.Root()) {
			t.Fatal("Invalid proof passed verification")
		}
	})
}

// 性能基准测试
func BenchmarkMerkleTree(b *testing.B) {
	sizes := []int{1_000, 10_000, 100_000}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size%d", size), func(b *testing.B) {
			hashes := generateHashes(size)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				tree := NewMerkleTree(hashes)

				// 生成证明性能
				b.StartTimer()
				proof, _ := tree.GenerateProof(hashes[size/2])
				b.StopTimer()

				// 验证性能
				b.StartTimer()
				VerifyProof(hashes[size/2], proof, tree.Root())
				b.StopTimer()
			}
		})
	}
}

// 边缘情况测试
func TestEdgeCases(t *testing.T) {
	t.Run("EmptyTree", func(t *testing.T) {
		tree := NewMerkleTree(nil)
		if tree.Root() != nil {
			t.Fatal("Empty tree root should be nil")
		}
	})

	t.Run("SingleNode", func(t *testing.T) {
		hash := []byte("single node")
		tree := NewMerkleTree([][]byte{hash})
		if !bytes.Equal(tree.Root(), hash) {
			t.Fatal("Single node root mismatch")
		}
	})

	t.Run("AllDuplicateHashes", func(t *testing.T) {
		hash := sha256.Sum256([]byte("duplicate"))
		hashes := [][]byte{hash[:], hash[:], hash[:]}
		tree := NewMerkleTree(hashes)
		proof, _ := tree.GenerateProof(hash[:])
		if !VerifyProof(hash[:], proof, tree.Root()) {
			t.Fatal("Duplicate hash verification failed")
		}
	})
}
