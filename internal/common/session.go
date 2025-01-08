package common

import (
	"encoding/hex"
	"fmt"
)

type SessionID []byte

func (s SessionID) String() string {
	return fmt.Sprintf("gmtls.SessionID(%s)", hex.EncodeToString(s))
}
