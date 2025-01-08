package common

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
