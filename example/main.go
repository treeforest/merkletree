package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/treeforest/merkletree"
)

func main() {
	data := [][]byte{
		[]byte("tx1"),
		[]byte("tx2"),
		[]byte("tx3"),
		[]byte("tx4"),
		[]byte("tx5"),
	}

	// 生成哈希列表
	hashes := make([][]byte, len(data))
	for i, d := range data {
		hash := sha256.Sum256(d)
		hashes[i] = hash[:]
	}

	// 构建默克尔树
	tree := merkletree.NewMerkleTree(hashes)
	fmt.Printf("Merkle root: %s\n", hex.EncodeToString(tree.Root()))
	for _, leaf := range tree.Leaves() {
		fmt.Printf("Leaf: %s\n", hex.EncodeToString(leaf))
	}

	// 生成并验证证明
	target := hashes[2]
	proof, err := tree.GenerateProof(target)
	if err != nil {
		panic(err)
	}

	// 打印证明路径
	fmt.Println("\nMerkle Proof:")
	for i, p := range proof.Hashes {
		fmt.Printf("[Level %d] %s\n", i+1, hex.EncodeToString(p))
	}

	// 验证证明有效性
	isValid := merkletree.VerifyProof(target, proof, tree.Root())
	fmt.Printf("\nVerification Result: %v\n", isValid)

	// 测试篡改数据
	tamperedData := []byte("tx0")
	isTamperedValid := merkletree.VerifyProof(tamperedData, proof, tree.Root())
	fmt.Printf("Tampered Verification: %v\n", isTamperedValid)
}
