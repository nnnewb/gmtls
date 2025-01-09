package handshaking

// CertificateRequestMessage 是 Certificate Request 消息，定义于 GM/T 0024-2014 第 6.4.4.4 节
type CertificateRequestMessage struct {
	// 要求客户端提供的证书类型的列表
	// 长度限制 1 <= n < 2^8
	CertificateTypes []CertificateType
	// 当 certificate type 是 ibc_params 时，本字段内容是 ibc 秘钥管理中心信任域名列表
	// 否则是信任 CA 的证书 DN 列表，包括根 CA 或二级 CA 的 DN。
	// 长度限制：0 <= n < 2^16
	CertificateAuthorities []DistinguishedName
}

// CertificateType 要求客户端提供的证书类型。定义于 GM/T 0024-2014 第 6.4.4.4 节
type CertificateType uint8

const (
	ClientCertificateTypeRSASign   CertificateType = 1
	ClientCertificateTypeECDSASign CertificateType = 64
	ClientCertificateTypeIBCParams CertificateType = 80
	ClientCertificateTypeMaximum   CertificateType = 255
)

var _ = ClientCertificateTypeMaximum

func (t CertificateType) String() string {
	switch t {
	case ClientCertificateTypeRSASign:
		return "rsa_sign"
	case ClientCertificateTypeECDSASign:
		return "ecdsa_sign"
	case ClientCertificateTypeIBCParams:
		return "ibc_params"
	default:
		return "unknown"
	}
}

// DistinguishedName IBC 秘钥管理中心信任的域名，或 信任 CA 的 DN 。
// 定义于 GM/T 0024-2014 第 6.4.4.4 节
type DistinguishedName []byte
