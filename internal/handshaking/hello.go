package handshaking

import "github.com/nnnewb/gmtls/internal/common"

// ClientHelloMessage 是 Client Hello 消息，定义于 GM/T 0024-2014 第 6.4.4.1.1 节
type ClientHelloMessage struct {
	// 客户端在这个会话中使用的协议版本
	ClientVersion common.ProtocolVersion

	// 客户端产生的随机信息，内容包括时钟和随机数
	Random common.Random

	// 客户端在连接中使用的会话标识，可变长，由服务端定义。
	// 没有可重用的会话标识时为空。反之表示客户端想重用会话。
	// 这个会话标识可能是之前的连接标识，当前连接标识，或其他处于连接状态的连接标识。
	// 会话标识生成后应一直保持直到被超时删除或与这个会话相关的连接遇到致命错误被关闭。
	// 一个会话失效或关闭时，与其相关的连接都应强制关闭。
	SessionID common.SessionID

	// 客户端支持的加密套件列表。客户端应按照密码套件的优先级顺序排列。优先级最高的套件应位于列表的第一个位置。
	// 如果会话标识不为空，则必须包含重用会话所使用的密码套件。
	// 服务端将在其中选择一个匹配的密码套件，如果没有与之匹配的密码套件，返回握手失败(handshake_failure)的报警消息并关闭连接。
	//
	// 小于等于 2^16 - 1 个加密套件。
	CipherSuites []common.CipherSuite

	// 客户端支持的压缩方法列表。客户端按照压缩方法的优先级顺序排列。优先级最高的方法应位于列表的第一个位置。
	// 服务端将在其中选择一个匹配的压缩方法，如果没有与之匹配的压缩方法，返回握手失败(handshake_failure)的报警消息并关闭连接。
	//
	// 小于等于 2^8 - 1 个压缩方法。
	CompressionMethods []common.CompressionMethod
}

// ServerHelloMessage 是 Server Hello 消息。定义于 GM/T 0024-2014 第 6.4.4.1.2 节。
// 如果能从客户端 Hello 消息中找到匹配的密码套件，则发送这个消息作为回复。
type ServerHelloMessage struct {
	// 服务端支持的协议版本。
	ServerVersion common.ProtocolVersion
	// 服务端产生的随机数
	Random common.Random
	// 会话标识。
	// 如果 ClientHelloMessage 消息中的会话标识不为空，且服务端存在与之匹配的会话，则服务端重用该标识对应的会话建立新连接，并在返回的 ServerHelloMessage 中
	// 带上与 ClientHelloMessage 相同的会话标识。反之，服务端创建一个新的会话，并返回新的会话标识。
	SessionID common.SessionID
	// 服务端从 ClientHelloMessage 中选择的密码套件。
	CipherSuite common.CipherSuite
	// 服务端从 ClientHelloMessage 中选择的压缩方法。
	CompressionMethod common.CompressionMethod
}
