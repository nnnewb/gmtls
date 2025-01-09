package handshaking

// CertificateMessage 是 Server/Client Certificate 消息。定义于 GM/T 0024-2014 第 6.4.4.2 节。
//
// 网络传输时的编码定义没找到标准来源，下面是传输格式
//
//	=========================== =============================================================================
//	 uint24 certificates_length  (repeat) (uint24 certificate_length) (opaque ASN.1 DER encoded certificate)
//	=========================== =============================================================================
//
// 参考 go 源码
//   - https://go.dev/src/crypto/tls/handshake_messages.go#L1370
type CertificateMessage struct {
	Certificates [][]byte
}
