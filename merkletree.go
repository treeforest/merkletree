package merkletree

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sort"
)

func New() *MerkleTree {
	return &MerkleTree{Nodes: make([][]Node, 0)}
}

// MerkleTree 默克尔树
type MerkleTree struct {
	Nodes [][]Node
}

// Node 默克尔树节点
type Node struct {
	Hash []byte // 当前节点的哈希值
}

// Root 返回默克尔树根哈希
func (t *MerkleTree) Root() []byte {
	return t.Nodes[len(t.Nodes)-1][0].Hash
}

// Build 根据交易哈希生成默克尔树
func (t *MerkleTree) Build(txHashes [][]byte) {
	// 1.对交易信息进行排序
	sort.Sort(Slices(txHashes))

	// 2.判断是否是奇数份交易
	if len(txHashes)%2 != 0 {
		// 若交易为奇数份，则拷贝最后一份
		txHashes = append(txHashes, txHashes[len(txHashes)-1])
	}

	// 3.构建叶子节点
	leafs := make([]Node, 0, len(txHashes))
	for _, txHash := range txHashes {
		leafs = append(leafs, Node{Hash: txHash})
	}

	// 4.递归构建默克尔树
	t.build(leafs)
}

func (t *MerkleTree) build(nodes []Node) {
	// 1.将节点存储到默克尔树中
	t.Nodes = append(t.Nodes, nodes)

	// 2.退出条件，节点个数为1的情况
	if len(nodes) == 1 {
		return
	}

	// 3.声明存储父节点信息的切片
	parents := make([]Node, 0)

	// 4.开始计算父节点信息
	n := len(nodes)
	for i := 0; i < n; i += 2 {
		// 4.1 计算父节点的哈希值
		l, r := i, i+1
		if r == n {
			// 奇数个节点
			r = l
		}
		hash := SortedHash(nodes[l].Hash, nodes[r].Hash)

		// 4.2 将父节点信息加入切片parents
		parents = append(parents, Node{Hash: hash[:]})
	}

	// 5. 递归构造父节点层
	t.build(parents)
}

// SortedHash 计算有序的哈希。规则：值小的哈希在计算时放在左边。
func SortedHash(hash1, hash2 []byte) []byte {
	var hash [32]byte
	if bytes.Compare(hash1, hash2) == -1 {
		hash = sha256.Sum256(append(hash1, hash2...))
	} else {
		hash = sha256.Sum256(append(hash2, hash1...))
	}
	return hash[:]
}

// GenMerkleProof 生成默克尔树根
func (t *MerkleTree) GenMerkleProof(txHash []byte) ([][]byte, error) {
	// 1.找到与txHash相同的叶子节点下标
	var i int = -1
	for j, node := range t.Nodes[0] {
		if bytes.Equal(node.Hash, txHash) {
			i = j
			break
		}
	}
	if i == -1 {
		return nil, errors.New("unknown txHash")
	}

	// 2.开始构造proof
	proof := make([][]byte, 0)
	for j := 0; j < len(t.Nodes)-1; j++ {
		// 2.1 获取第j层的节点切片信息
		level := t.Nodes[j]

		// 2.2 找到兄弟节点的索引
		var k int
		if i%2 == 0 {
			// 2.2.1 索引为奇数，则兄弟节点在节点的右边。
			k = i + 1
			if k == len(level) {
				k = i
			}
		} else {
			// 2.2.2 索引为奇数，则兄弟节点在节点的左边。
			k = i - 1
		}

		// 2.3 注意：将兄弟节点的哈希加入proof
		proof = append(proof, level[k].Hash)

		// 2.4 往上遍历父节点
		i = i / 2
	}

	// 3.返回最终的proof
	return proof, nil
}

// Verify 验证交易
func (t *MerkleTree) Verify(txHash []byte, proof [][]byte) bool {
	return Verify(txHash, proof, t.Root())
}

// Verify 验证交易是否存在目标默克尔树中。注意：在这个过程中，
// txHash及proof由别人提供，你所知道的是merkleRoot。
// 参数
// 	txHash: 待验证交易的哈希。
//	proof: 验证交易的默克尔树证明。
// 	merkleRoot: 默克尔树根。
func Verify(txHash []byte, proof [][]byte, merkleRoot []byte) bool {
	dst := txHash
	for _, h := range proof {
		dst = SortedHash(dst, h)
	}
	return bytes.Equal(dst, merkleRoot)
}

// Slices 定义[][]byte排序的类型
type Slices [][]byte

func (s Slices) Len() int           { return len(s) }
func (s Slices) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s Slices) Less(i, j int) bool { return bytes.Compare(s[i], s[j]) == -1 }
