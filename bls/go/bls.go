package main

import (
	"crypto/rand"

	bls12381 "github.com/kilic/bls12-381"
	"github.com/stretchr/testify/assert"
)

func main() {
	//初始化群G1
	g1 := bls12381.NewG1()
	//随机生成私钥,私钥要小于G1的阶
	privateKey, err := rand.Int(rand.Reader, bls12381.NewG1().Q())
	if err != nil {
		panic(err)
	}
	//获取G1的基点
	G := g1.One()
	// 通过 privateKey * G 计算公钥
	publicKey := g1.New()
	g1.MulScalar(publicKey, G, new(bls12381.Fr).FromBytes(privateKey.Bytes()))
	// 对消息进行哈希,映射到G2点
	msg := []byte("hello world!")
	g2 := bls12381.NewG2()
	hashPoint, err := g2.HashToCurve(msg, []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"))
	if err != nil {
		panic(err)
	}
	//通过 privateKey * hashPoint 计算签名
	hashsignPoint := g2.New()
	g2.MulScalar(hashsignPoint, hashPoint, new(bls12381.Fr).FromBytes(privateKey.Bytes()))
	//生成 e(G,hashsignPoint) 和 e(publicKey,hashPoint)
	e1 := bls12381.NewEngine().AddPair(publicKey, hashPoint)
	e2 := bls12381.NewEngine().AddPair(G, hashsignPoint)
	//验证e1 和 e2 是否相等
	assert.Equal(&assert.CollectT{}, true, e1.Result().Equal(e2.Result()), "BLS签名失败")
}
