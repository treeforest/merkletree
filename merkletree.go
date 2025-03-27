package merkletree

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// Proof 包含路径哈希和方向标记
type Proof struct {
	Hashes [][]byte
	IsLeft []bool // true表示兄弟节点在左侧
}

type MerkleTree struct {
	leaves [][]byte
	root   []byte
}

func NewMerkleTree(txHashes [][]byte) *MerkleTree {
	tree := &MerkleTree{}
	tree.build(txHashes)

	return tree
}

// Build 构建Merkle树（保留原始顺序）
func (t *MerkleTree) build(txHashes [][]byte) {
	t.leaves = make([][]byte, len(txHashes))
	copy(t.leaves, txHashes)
	t.root = t.buildRoot(txHashes)
}

// buildRoot 迭代构建树根（优化内存）
func (t *MerkleTree) buildRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}

	currentLevel := leaves
	for len(currentLevel) > 1 {
		nextLevel := make([][]byte, 0, (len(currentLevel)+1)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			var right []byte
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				right = currentLevel[i] // 奇数节点复制
			}
			combined := orderedHash(currentLevel[i], right)
			nextLevel = append(nextLevel, combined)
		}
		currentLevel = nextLevel
	}

	return currentLevel[0]
}

// Root 返回根哈希
func (t *MerkleTree) Root() []byte {
	return t.root
}

// Leaves 返回所有叶子哈希
func (t *MerkleTree) Leaves() [][]byte {
	return t.leaves
}

// GenerateProof 生成包含顺序标记的证明
func (t *MerkleTree) GenerateProof(txHash []byte) (*Proof, error) {
	index := -1
	for i, leaf := range t.leaves {
		if bytes.Equal(leaf, txHash) {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, fmt.Errorf("txHash %x not found", txHash)
	}

	proof := &Proof{
		Hashes: make([][]byte, 0),
		IsLeft: make([]bool, 0),
	}

	currentLevel := t.leaves
	currentIndex := index

	for len(currentLevel) > 1 {
		var siblingIndex int
		var isLeft bool

		if currentIndex%2 == 0 {
			siblingIndex = currentIndex + 1
			isLeft = false // 兄弟在右侧
		} else {
			siblingIndex = currentIndex - 1
			isLeft = true // 兄弟在左侧
		}

		if siblingIndex >= len(currentLevel) {
			siblingIndex = currentIndex
		}

		proof.Hashes = append(proof.Hashes, currentLevel[siblingIndex])
		proof.IsLeft = append(proof.IsLeft, isLeft)

		// 计算父节点索引
		currentIndex /= 2
		currentLevel = buildParentLevelWithOrder(currentLevel)
	}

	return proof, nil
}

// VerifyProof 根据顺序标记验证
func VerifyProof(txHash []byte, proof *Proof, merkleRoot []byte) bool {
	current := txHash
	for i, h := range proof.Hashes {
		if proof.IsLeft[i] {
			current = orderedHash(h, current) // 兄弟在左侧
		} else {
			current = orderedHash(current, h) // 兄弟在右侧
		}
	}

	return bytes.Equal(current, merkleRoot)
}

// 以下为辅助函数
func orderedHash(a, b []byte) []byte {
	if bytes.Compare(a, b) < 0 {
		return hashPair(a, b)
	}

	return hashPair(b, a)
}

func hashPair(a, b []byte) []byte {
	var combined []byte
	combined = append(combined, a...)
	combined = append(combined, b...)
	hash := sha256.Sum256(combined)

	return hash[:]
}

func buildParentLevelWithOrder(level [][]byte) [][]byte {
	parentLevel := make([][]byte, 0)
	for i := 0; i < len(level); i += 2 {
		if i+1 < len(level) {
			parentLevel = append(parentLevel, orderedHash(level[i], level[i+1]))
		} else {
			parentLevel = append(parentLevel, orderedHash(level[i], level[i]))
		}
	}

	return parentLevel
}
