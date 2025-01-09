package gmtls

import "strconv"

// An AlertError is a TLS alert.
//
// When using a QUIC transport, QUICConn methods will return an error
// which wraps AlertError rather than sending a TLS alert.
type AlertError uint8

func (e AlertError) Error() string {
	return alert(e).String()
}

type alert uint8

const (
	// alert level
	alertLevelWarning = 1
	alertLevelError   = 2
)

const (
	alertCloseNotify            alert = 0
	alertUnexpectedMessage      alert = 10
	alertBadRecordMAC           alert = 20
	alertDecryptionFailed       alert = 21
	alertRecordOverflow         alert = 22
	alertDecompressionFailure   alert = 30
	alertHandshakeFailure       alert = 40
	alertBadCertificate         alert = 42
	alertUnsupportedCertificate alert = 43
	alertCertificateRevoked     alert = 44
	alertCertificateExpired     alert = 45
	alertCertificateUnknown     alert = 46
	alertIllegalParameter       alert = 47
	alertUnknownCA              alert = 48
	alertAccessDenied           alert = 49
	alertDecodeError            alert = 50
	alertDecryptError           alert = 51
	alertExportRestriction      alert = 60
	alertProtocolVersion        alert = 70
	alertInsufficientSecurity   alert = 71
	alertInternalError          alert = 80
	alertInappropriateFallback  alert = 86
	alertUserCanceled           alert = 90

	// 定义于 GM/T 0024-2014 第 6.4.2.2 节
	alertUnsupportedSite2site alert = 200
	alertNoArea               alert = 201
	alertUnsupportedAreatype  alert = 202
	alertBadIbcparam          alert = 203
	alertUnsupportedIbcparam  alert = 204
	alertIdentityNeed         alert = 205
)

var alertText = map[alert]string{
	alertCloseNotify:            "close notify",
	alertUnexpectedMessage:      "unexpected message",
	alertBadRecordMAC:           "bad record MAC",
	alertDecryptionFailed:       "decryption failed",
	alertRecordOverflow:         "record overflow",
	alertDecompressionFailure:   "decompression failure",
	alertHandshakeFailure:       "handshake failure",
	alertBadCertificate:         "bad certificate",
	alertUnsupportedCertificate: "unsupported certificate",
	alertCertificateRevoked:     "revoked certificate",
	alertCertificateExpired:     "expired certificate",
	alertCertificateUnknown:     "unknown certificate",
	alertIllegalParameter:       "illegal parameter",
	alertUnknownCA:              "unknown certificate authority",
	alertAccessDenied:           "access denied",
	alertDecodeError:            "error decoding message",
	alertDecryptError:           "error decrypting message",
	alertExportRestriction:      "export restriction",
	alertProtocolVersion:        "protocol version not supported",
	alertInsufficientSecurity:   "insufficient security level",
	alertInternalError:          "internal error",
	alertInappropriateFallback:  "inappropriate fallback",
	alertUserCanceled:           "user canceled",

	// 定义于 GM/T 0024-2014 第 6.4.2.2 节
	alertUnsupportedSite2site: "不支持 site2site",
	alertNoArea:               "没有保护域",
	alertUnsupportedAreatype:  "不支持的保护域类型",
	alertBadIbcparam:          "接收到一个无效的IBC公共参数",
	alertUnsupportedIbcparam:  "不支持IBC公共参数中定义的信息",
	alertIdentityNeed:         "缺少对方的IBC标识",
}

func (e alert) String() string {
	s, ok := alertText[e]
	if ok {
		return "tls: " + s
	}
	return "tls: alert(" + strconv.Itoa(int(e)) + ")"
}

func (e alert) Error() string {
	return e.String()
}
