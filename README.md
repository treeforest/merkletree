# merkletree

高性能Merkle Tree实现，专为区块链交易验证和数据完整性检查设计，支持高效证明生成与验证（O(log n)时间复杂度）

## 特性
### 🚀 核心功能

- **确定性哈希排序**：通过orderedHash实现字典序排列，消除哈希顺序歧义
- **奇数节点处理**：自动复制末节点构建完全二叉树

🔐 验证机制

- **增量验证**：无需重建完整树结构
- **防篡改检测**：敏感数据变更立即失效验证
- **路径压缩**：Proof结构仅存储必要兄弟节点

## 安装

```go
go get github.com/treeforest/merkletree
```

## 使用示例

```go
package main

import (
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

	// 构建默克尔树
	tree := merkletree.NewMerkleTree(data)
	fmt.Printf("Merkle root: %s\n", hex.EncodeToString(tree.Root()))
	for _, leaf := range tree.Leaves() {
		fmt.Printf("Leaf: %s\n", hex.EncodeToString(leaf))
	}

	// 生成并验证证明
	target := []byte("tx2")
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
```

## 许可证

MIT License