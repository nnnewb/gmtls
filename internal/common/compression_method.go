package common

// CompressionMethod 定义于 GM/T 0024-2014 第 6.3.1 节
// 表示压缩算法
type CompressionMethod uint8

const (
	CompressionMethodNull    CompressionMethod = 0
	CompressionMethodMaximum CompressionMethod = 255
)

var _ = CompressionMethodMaximum

func (c CompressionMethod) String() string {
	switch c {
	case CompressionMethodNull:
		return "null"
	default:
		return "unknown"
	}
}
