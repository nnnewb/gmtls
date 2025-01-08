package common

import (
	"encoding/hex"
	"fmt"
)

type Random struct {
	GMTUnixTime uint32   // 格林威治时间 Unix 32位时间戳，单位秒
	RandomBytes [28]byte // 随机字节数组
}

func (r Random) String() string {
	return fmt.Sprintf("gmtls.Random(GMTUnixTime=%d, RandomBytes=%s)", r.GMTUnixTime, hex.EncodeToString(r.RandomBytes[:]))
}
