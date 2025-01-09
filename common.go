package gmtls

import (
	"crypto"
	"crypto/x509"
	"io"
	"time"

	x510 "github.com/tjfoc/gmsm/x509"

	"github.com/nnnewb/gmtls/internal/common"
)

// ConnectionState 记录了连接的基本 TLS 详细信息。
type ConnectionState struct {
	// Version 是连接使用的 TLS 版本（例如：VersionTLS12）。
	Version common.ProtocolVersion

	// HandshakeComplete 表示握手是否已经完成。
	HandshakeComplete bool

	// CipherSuite 是为连接协商的加密套件（例如：
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256）。
	CipherSuite uint16

	// PeerCertificates 是对等方发送的已解析证书列表，按发送顺序排列。
	// 第一个元素是用于验证连接的叶证书。
	//
	// 在客户端，此列表不能为空。在服务器端，如果 Config.ClientAuth 不是
	// RequireAnyClientCert 或 RequireAndVerifyClientCert，则此列表可以为空。
	//
	// 不应修改 PeerCertificates 及其内容。
	PeerCertificates []*x509.Certificate

	// VerifiedChains 是一个或多个链的列表，其中第一个元素是 PeerCertificates[0]，
	// 最后一个元素来自 Config.RootCAs（在客户端）或 Config.ClientCAs（在服务器端）。
	//
	// 在客户端，如果 Config.InsecureSkipVerify 为 false，则会设置此字段。
	// 在服务器端，如果 Config.ClientAuth 设置为 VerifyClientCertIfGiven（且对等方提供了证书）
	// 或 RequireAndVerifyClientCert，则会设置此字段。
	//
	// 不应修改 VerifiedChains 及其内容。
	VerifiedChains [][]*x509.Certificate
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

const (
	// NoClientCert indicates that no client certificate should be requested
	// during the handshake, and if any certificates are sent they will not
	// be verified.
	NoClientCert ClientAuthType = iota
	// RequestClientCert indicates that a client certificate should be requested
	// during the handshake, but does not require that the client send any
	// certificates.
	RequestClientCert
	// RequireAnyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one certificate is required to be
	// sent by the client, but that certificate is not required to be valid.
	RequireAnyClientCert
	// VerifyClientCertIfGiven indicates that a client certificate should be requested
	// during the handshake, but does not require that the client sends a
	// certificate. If the client does send a certificate it is required to be
	// valid.
	VerifyClientCertIfGiven
	// RequireAndVerifyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one valid certificate is required
	// to be sent by the client.
	RequireAndVerifyClientCert
)

// Certificate 是一个证书链，包含一个或多个证书，叶证书在前。
type Certificate struct {
	// Certificate 包含证书链中的每个证书的 ASN.1 DER 编码。
	Certificate [][]byte

	// PrivateKey 包含与 Leaf 中公钥对应的私钥。
	// 该私钥必须实现 crypto.Signer，并且其 PublicKey 必须是 RSA、ECDSA 或 Ed25519 类型。
	// 对于 TLS 1.2 及以下版本的服务器，它也可以实现 crypto.Decrypter 并具有 RSA PublicKey。
	PrivateKey crypto.PrivateKey

	// Leaf 是叶证书的解析形式，可以使用 x509.ParseCertificate 初始化以减少每次握手的处理开销。
	// 如果为 nil，则会在需要时解析叶证书。
	Leaf *x510.Certificate
}

// Config 结构用于配置 TLS 客户端或服务器。
// 传递给 TLS 函数后，不得修改该结构。
// Config 可以重复使用；tls 包也不会修改它。
type Config struct {
	// Rand 提供用于生成 nonces 和 RSA 盲化的熵源。
	// 如果 Rand 为 nil，TLS 使用 crypto/rand 包中的加密随机读取器。
	// 该 Reader 必须能够安全地被多个 goroutine 使用。
	Rand io.Reader

	// Time 返回自纪元以来的秒数作为当前时间。
	// 如果 Time 为 nil，TLS 使用 time.Now。
	Time func() time.Time

	// Certificates 包含一个或多个要呈现给连接另一端的证书链。
	// 第一个与对等方要求兼容的证书会自动选择。
	//
	// 服务器配置必须设置 Certificates
	// 进行客户端认证的客户端可以设置 Certificates 。
	//
	// 注意：如果有多个 Certificates，并且它们没有设置可选字段 Leaf，
	// 证书选择会在每次握手时产生显著的性能开销。
	Certificates []Certificate

	// VerifyPeerCertificate 如果不为 nil，在正常的证书验证之后，无论是 TLS 客户端还是服务器都会调用此函数。
	//
	// 它接收对等方提供的原始 ASN.1 证书以及正常处理找到的任何已验证链。
	//
	// 如果它返回非 nil 错误，则握手将被中止，并返回该错误。
	//
	// 如果正常的验证失败，那么在考虑此回调之前握手就会被中止。
	//
	// 如果正常的验证被禁用（客户端设置 InsecureSkipVerify 时，或服务器设置 ClientAuth 为 RequestClientCert
	// 或 RequireAnyClientCert 时），则此回调会被考虑，但 verifiedChains 参数将始终为 nil。
	//
	// 当 ClientAuth 设置为 NoClientCert 时，此回调在服务器端不会被调用。
	//
	// 如果 ClientAuth 设置为 RequestClientCert 或 VerifyClientCertIfGiven，服务器端的 rawCerts 可能为空。
	//
	// 在重新协商的连接上不会调用此回调，因为证书在重新协商时不会重新验证。
	//
	// 不应修改 verifiedChains 及其内容。
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection 如果不为 nil， 在正常的证书验证和 VerifyPeerCertificate 之后，
	// 无论是 TLS 客户端还是服务器都会调用此函数。
	//
	// 如果它返回非 nil 错误，则握手将被中止，并返回该错误。
	//
	// 如果正常的验证失败，那么在考虑此回调之前握手就会被中止。
	//
	// 此回调会针对所有连接运行，包括重新协商的连接，无论 InsecureSkipVerify 或 ClientAuth 的设置如何。
	VerifyConnection func(ConnectionState) error

	// RootCAs 定义了客户端在验证服务器证书时使用的根证书权威机构集合。
	// 如果 RootCAs 为 nil， TLS 将使用主机的根 CA 集合。
	RootCAs *x509.CertPool

	// ClientAuth 确定了服务器对 TLS 客户端认证的策略。默认值为 NoClientCert（不要求客户端证书）。
	ClientAuth ClientAuthType

	// ClientCAs 定义了服务器在需要根据 ClientAuth 策略验证客户端证书时使用的根证书权威机构集合。
	ClientCAs *x510.CertPool

	// InsecureSkipVerify 控制客户端是否验证服务器的证书链和主机名。
	// 如果 InsecureSkipVerify 为 true ，tls 将接受服务器提供的任何证书以及该证书中的任何主机名。
	// 在这种模式下，TLS 容易受到中间人攻击，除非使用自定义验证。
	// 此选项仅应在测试时使用，或与 VerifyConnection 或 VerifyPeerCertificate 结合使用。
	InsecureSkipVerify bool

	// CipherSuites 是 GM/T 0024-2014 规定的 CipherSuite 列表。
	// 此列表的顺序无关紧要。如果 CipherSuites 为空，则使用默认的 CipherSuite 列表。
	// 当前仅支持 ECC_SM4_SM3 密码套件。
	CipherSuites []common.CipherSuite
}
