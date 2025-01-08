package internal

import (
	"fmt"
)

type SecurityParameters struct {
	Entity               ConnectionEnd       // 表示本端在连接中的角色，为客户端或服务端
	BulkCipherAlgorithm  BulkCipherAlgorithm // 表示数据加解密的密码算法
	CipherType           CipherType          // 表示密码算法的类型
	KeyMaterialLength    uint8               //
	MacAlgorithm         MacAlgorithm        // 表示用于计算和校验消息完整性的杂凑算法。
	HashSize             uint8               //
	CompressionAlgorithm CompressionMethod   // 表示压缩算法
	MasterSecret         [48]byte            // 协商过程中由预主秘钥、客户端随机数、服务端随机数计算而成的 48 字节秘钥
	ClientRandom         [32]byte            // 表示客户端随机数
	ServerRandom         [32]byte            // 表示服务端随机数
	RecordIVLength       uint8               // IV 长度
	MacLength            uint8               // MAC 长度
}

func (s *SecurityParameters) String() string {
	return fmt.Sprintf(
		"gmtls.SecurityParameters(Entity=%s, "+
			"BulkCipherAlgorithm=%s, "+
			"CipherType=%s, "+
			"KeyMaterialLength=%d, "+
			"MacAlgorithm=%s, "+
			"HashSize=%d, "+
			"CompressionAlgorithm=%s, "+
			"MasterSecret.length=%d, "+
			"ClientRandom.length=%d, "+
			"ServerRandom.length=%d, "+
			"RecordIVLength=%d, "+
			"MacLength=%d)",
		s.Entity,
		s.BulkCipherAlgorithm,
		s.CipherType,
		s.KeyMaterialLength,
		s.MacAlgorithm,
		s.HashSize,
		s.CompressionAlgorithm,
		len(s.MasterSecret),
		len(s.ClientRandom),
		len(s.ServerRandom),
		s.RecordIVLength,
		s.MacLength,
	)
}

// ConnectionEnd 定义于 GM/T 0024-2014 第 6.3.1 节
// 表示本端在连接中的角色，为客户端或服务端
type ConnectionEnd uint8

const (
	ConnectionEndServer ConnectionEnd = 1
	ConnectionEndClient ConnectionEnd = 2
)

func (c ConnectionEnd) String() string {
	switch c {
	case ConnectionEndServer:
		return "server"
	case ConnectionEndClient:
		return "client"
	default:
		return "unknown"
	}
}

// BulkCipherAlgorithm 定义于 GM/T 0024-2014 第 6.3.1 节
// 表示数据加解密的密码算法
type BulkCipherAlgorithm uint8

const (
	BulkCipherAlgorithmSM1 BulkCipherAlgorithm = 1
	BulkCipherAlgorithmSM4 BulkCipherAlgorithm = 2
)

func (b BulkCipherAlgorithm) String() string {
	switch b {
	case BulkCipherAlgorithmSM1:
		return "SM1"
	case BulkCipherAlgorithmSM4:
		return "SM4"
	default:
		return "unknown"
	}
}

// CipherType 定义于 GM/T 0024-2014 第 6.3.1 节
// 表示密码算法的类型
type CipherType uint8

const (
	CipherTypeBlock CipherType = 1
)

func (c CipherType) String() string {
	switch c {
	case CipherTypeBlock:
		return "block"
	default:
		return "unknown"
	}
}

// MacAlgorithm 定义于 GM/T 0024-2014 第 6.3.1 节
// 表示用于计算和校验消息完整性的杂凑算法。
type MacAlgorithm uint8

const (
	MacAlgorithmSHA1 MacAlgorithm = 1
	MacAlgorithmSM3  MacAlgorithm = 2
)

func (m MacAlgorithm) String() string {
	switch m {
	case MacAlgorithmSHA1:
		return "SHA1"
	case MacAlgorithmSM3:
		return "SM3"
	default:
		return "unknown"
	}
}

// CompressionMethod 定义于 GM/T 0024-2014 第 6.3.1 节
// 表示压缩算法
type CompressionMethod uint8

const (
	CompressionMethodNull    CompressionMethod = 0
	CompressionMethodMaximum CompressionMethod = 255
)

var _ = CompressionMethodMaximum

func (c CompressionMethod) String() string {
	switch c {
	case CompressionMethodNull:
		return "null"
	default:
		return "unknown"
	}
}
