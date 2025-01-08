package handshaking

// ChangeCipherSpecMessage 握手协议族中的密码规格变更协议。定义于 GM/T 0024-2014 第 6.4.1 节。
type ChangeCipherSpecMessage struct {
	Type ChangeCipherSpecType
}

// ChangeCipherSpecType 密码规格变更协议的 Type 枚举值，定义于 GM/T 0024-2014 第 6.4.1 节。
type ChangeCipherSpecType uint8

const (
	ChangeCipherSpecTypeChangeCipherSpec ChangeCipherSpecType = 1
	ChangeCipherSpecTypeMaximum          ChangeCipherSpecType = 255
)

var _ = ChangeCipherSpecTypeMaximum

func (c ChangeCipherSpecType) String() string {
	switch c {
	case ChangeCipherSpecTypeChangeCipherSpec:
		return "change_cipher_spec"
	default:
		return "unknown"
	}
}
