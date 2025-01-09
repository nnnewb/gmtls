package common

// CipherSuite 密码套件。定义于 GM/T 0024-2014 第 6.4.4.1.1 节。
// 每个密码套件包含一个秘钥交换算法、一个加密算法和一个校验算法。
type CipherSuite uint16

const (
	CipherSuite_ECDHE_SM1_SM3 = 0xe001
	CipherSuite_ECC_SM1_SM3   = 0xe003
	CipherSuite_IBSDH_SM1_SM3 = 0xe005
	CipherSuite_IBC_SM1_SM3   = 0xe007
	CipherSuite_RSA_SM1_SM3   = 0xe009
	CipherSuite_RSA_SM1_SHA1  = 0xe00a
	CipherSuite_ECDHE_SM4_SM3 = 0xe011
	CipherSuite_ECC_SM4_SM3   = 0xe013
	CipherSuite_IBSDH_SM4_SM3 = 0xe015
	CipherSuite_IBC_SM4_SM3   = 0xe017
	CipherSuite_RSA_SM4_SM3   = 0xe019
	CipherSuite_RSA_SM4_SHA1  = 0xe01a
)

func (c CipherSuite) String() string {
	switch c {
	case CipherSuite_ECDHE_SM1_SM3:
		return "ECDHE_SM1_SM3"
	case CipherSuite_ECC_SM1_SM3:
		return "ECC_SM1_SM3"
	case CipherSuite_IBSDH_SM1_SM3:
		return "IBSDH_SM1_SM3"
	case CipherSuite_IBC_SM1_SM3:
		return "IBC_SM1_SM3"
	case CipherSuite_RSA_SM1_SM3:
		return "RSA_SM1_SM3"
	case CipherSuite_RSA_SM1_SHA1:
		return "RSA_SM1_SHA1"
	case CipherSuite_ECDHE_SM4_SM3:
		return "ECDHE_SM4_SM3"
	case CipherSuite_ECC_SM4_SM3:
		return "ECC_SM4_SM3"
	case CipherSuite_IBSDH_SM4_SM3:
		return "IBSDH_SM4_SM3"
	case CipherSuite_IBC_SM4_SM3:
		return "IBC_SM4_SM3"
	case CipherSuite_RSA_SM4_SM3:
		return "RSA_SM4_SM3"
	case CipherSuite_RSA_SM4_SHA1:
		return "RSA_SM4_SHA1"
	default:
		return "unknown"
	}
}

// KeyExchangeAlgorithm 密钥交换算法。定义于 GM/T 0024-2014 第 6.4.4.3 节。
type KeyExchangeAlgorithm uint8

const (
	KeyExchangeAlgorithmECDHE KeyExchangeAlgorithm = 1
	KeyExchangeAlgorithmECC   KeyExchangeAlgorithm = 2
	KeyExchangeAlgorithmIBSDH KeyExchangeAlgorithm = 3
	KeyExchangeAlgorithmIBC   KeyExchangeAlgorithm = 4
	KeyExchangeAlgorithmRSA   KeyExchangeAlgorithm = 5
)

func (a KeyExchangeAlgorithm) String() string {
	switch a {
	case KeyExchangeAlgorithmECDHE:
		return "ECDHE"
	case KeyExchangeAlgorithmECC:
		return "ECC"
	case KeyExchangeAlgorithmIBSDH:
		return "IBSDH"
	case KeyExchangeAlgorithmIBC:
		return "IBC"
	case KeyExchangeAlgorithmRSA:
		return "RSA"
	default:
		return "unknown"
	}
}
