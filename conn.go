package gmtls

import (
	"crypto/x509"
	"net"
	"sync"
	"sync/atomic"
	"time"

	gmx509 "github.com/tjfoc/gmsm/x509"

	"github.com/nnnewb/gmtls/internal/common"
)

type Conn struct {
	conn     net.Conn
	isClient bool

	// isHandshakeComplete 表示连接当前是否正在传输应用数据（即不处于握手状态）。
	// isHandshakeComplete 为 true 意味着 handshakeErr == nil。
	isHandshakeComplete atomic.Bool

	// 在握手后保持不变；由 handshakeMutex 保护
	handshakeMutex sync.Mutex
	handshakeErr   error                  // handshakeErr 是握手过程中产生的错误
	version        common.ProtocolVersion // version 是 TLS 版本
	haveVersion    bool                   // haveVersion 表示版本是否已协商
	config         *Config                // config 是传递给构造函数的配置

	// cipherSuite 是为连接协商的加密套件
	cipherSuite CipherSuite

	// peerCertificates 是对等方发送的证书链
	peerCertificates []*gmx509.Certificate

	// verifiedChains 包含我们构建的证书链，而不是服务器提供的证书链。
	verifiedChains [][]*x509.Certificate

	// clientFinishedIsFirst 表示在最近的握手过程中，客户端是否首先发送了 Finished 消息。
	// 这是因为第一个传输的 Finished 消息是 tls-unique 通道绑定值。
	clientFinishedIsFirst bool

	// closeNotifyErr 是发送 alertCloseNotify 记录时的任何错误。
	closeNotifyErr error

	// closeNotifySent 表示 Conn 是否尝试发送过 alertCloseNotify 记录。
	closeNotifySent bool
}

// LocalAddr 返回本地网络地址。
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr 返回远程网络地址。
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline 设置连接的读写截止时间。
// t 为零值表示 [Conn.Read] 和 [Conn.Write] 不会超时。
// 如果 Write 超时，TLS 状态将损坏，所有未来的写操作将返回相同的错误。
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline 设置底层连接的读取截止时间。
// t 为零值表示 [Conn.Read] 不会超时。
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置底层连接的写入截止时间。
// t 为零值表示 [Conn.Write] 不会超时。
// 如果 [Conn.Write] 超时，TLS 状态将损坏，所有未来的写操作将返回相同的错误。
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// NetConn 返回被 c 包装的底层连接。
// 注意：直接对这个连接进行读写操作会破坏 TLS 会话。
func (c *Conn) NetConn() net.Conn {
	return c.conn
}
