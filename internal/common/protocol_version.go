package common

import (
	"fmt"
)

// ProtocolVersion 定义于 GM/T 0024-2014 第 6.3.2.1 节
// 记录层协议版本号，GM/T 0024-2014 标准的协议版本号固定为 1.1
type ProtocolVersion [2]uint8

func (v ProtocolVersion) Major() uint8 {
	return v[0]
}

func (v ProtocolVersion) Minor() uint8 {
	return v[1]
}

func (v ProtocolVersion) String() string {
	return fmt.Sprintf("gmtls.ProtocolVersion(major=%d, minor=%d)", v[0], v[1])
}
