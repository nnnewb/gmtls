package internal

import (
	"fmt"
)

// TLSFragment 基于 GM/T 0024-2014 第 6.3.2 节定义的公共片段结构。
type TLSFragment struct {
	Type     TLSFragmentContentType
	Version  TLSFragmentProtocolVersion
	Length   uint16
	Fragment []byte
}

func (t *TLSFragment) String() string {
	return fmt.Sprintf("gmtls.TLSFragment(type=%s, version=%s, length=%d, fragment.len=%d)", t.Type, t.Version, t.Length, len(t.Fragment))
}

// TLSCiphertext 定义于 GM/T 0024-2014 第 6.3.2.3 节
// 表示 TLSCompressed 加密后的数据结构。
//
// 分组加密前明文必须对齐到分组长度，padding 算法固定使用 PKCS#7 ，待填充长度不超过 255
// type TLSCiphertext struct {
// 	Type     TLSFragmentContentType     // 同 TLSPlaintext.Type
// 	Version  TLSFragmentProtocolVersion // 同 TLSPlaintext.Version
// 	Length   uint16                     // Length of Fragment
// 	Fragment []byte                     // IV + Ciphertext; ciphertext = encrypt(plaintext + MAC)
// }
//
// func (t *TLSCiphertext) String() string {
// 	return fmt.Sprintf("gmtls.TLSCiphertext(type=%s, version=%s, length=%d, fragment.len=%d)", t.Type, t.Version, t.Length, len(t.Fragment))
// }

// TLSCompressed 定义于 GM/T 0024-2014 第 6.3.2.2 节
// 所有的记录都使用当前会话状态指定的压缩算法进行压缩。当前会话指定的压缩算法被初始化为空算法。
// 压缩算法将 TLSPlaintext 转换为 TLSCompressed 结构。
// 压缩后的数据长度最多只能增长 1024 字节。如果解压缩后数据长度超过 2^14 字节，则报告一个 decompression failure 致命错误。
// type TLSCompressed struct {
// 	Type     TLSFragmentContentType     // 同 TLSPlaintext.Type
// 	Version  TLSFragmentProtocolVersion // 同 TLSPlaintext.Version
// 	Length   uint16                     // 以字节为单位的片段长度，小于等于 2^14+1024
// 	Fragment []byte                     // TLSPlaintext.Fragment 的压缩形式
// }
//
// func (t *TLSCompressed) String() string {
// 	return fmt.Sprintf("gmtls.TLSCompressed(type=%s, version=%s, length=%d, fragment.len=%d)", t.Type, t.Version, t.Length, len(t.Fragment))
// }

// TLSPlaintext 定义于 GM/T 0024-2014 第 6.3.2.1 节
// type TLSPlaintext struct {
// 	Type     TLSFragmentContentType     // 片段的记录层协议类型，定义于 6.3.2.1a
// 	Version  TLSFragmentProtocolVersion // GM/T 0024-2014 标准版本号为 1.1
// 	Length   uint16                     // 以字节为单位的片段长度，小于或等于 2^14
// 	Fragment []byte                     // 将要传输的数据。记录层协议不关注具体内容。
// }
//
// func (t *TLSPlaintext) String() string {
// 	return fmt.Sprintf("gmtls.TLSPlaintext(type=%s, version=%s, length=%d, fragment.len=%d)", t.Type, t.Version, t.Length, len(t.Fragment))
// }

// TLSFragmentContentType 定义于 GM/T 0024-2014 第 6.3.2.1 节
// 片段的记录层协议类型
type TLSFragmentContentType uint8

const (
	ContentTypeChangeCipherSpec TLSFragmentContentType = 20  // change_cipher_spec
	ContentTypeAlert            TLSFragmentContentType = 21  // alert defined
	ContentTypeHandshake        TLSFragmentContentType = 22  // handshake
	ContentTypeApplicationData  TLSFragmentContentType = 23  // application_data
	ContentTypeSite2Site        TLSFragmentContentType = 80  // site2site
	ContentTypeMaximum          TLSFragmentContentType = 255 // unused
)

var _ = ContentTypeMaximum

func (c TLSFragmentContentType) String() string {
	switch c {
	case ContentTypeChangeCipherSpec:
		return "change_cipher_spec"
	case ContentTypeAlert:
		return "alert"
	case ContentTypeHandshake:
		return "handshake"
	case ContentTypeApplicationData:
		return "application_data"
	case ContentTypeSite2Site:
		return "site2site"
	default:
		return "unknown"
	}
}

// TLSFragmentProtocolVersion 定义于 GM/T 0024-2014 第 6.3.2.1 节
// 记录层协议版本号，GM/T 0024-2014 标准的协议版本号固定为 1.1
type TLSFragmentProtocolVersion [2]uint8

func (v TLSFragmentProtocolVersion) Major() uint8 {
	return v[0]
}

func (v TLSFragmentProtocolVersion) Minor() uint8 {
	return v[1]
}

func (v TLSFragmentProtocolVersion) String() string {
	return fmt.Sprintf("gmtls.TLSFragmentProtocolVersion(major=%d, minor=%d)", v[0], v[1])
}
