package handshaking

// AlertMessage 握手协议族中的报警协议。定义于 GM/T 0024-2014 第 6.4.2 节。
type AlertMessage struct {
	Level       AlertLevel
	Description AlertDescription
}

type AlertLevel uint8

const (
	AlertLevelWarning AlertLevel = 1
	AlertLevelFatal   AlertLevel = 2
	AlertLevelMaximum AlertLevel = 255
)

var _ = AlertLevelMaximum

func (a AlertLevel) String() string {
	switch a {
	case AlertLevelWarning:
		return "warning"
	case AlertLevelFatal:
		return "fatal"
	default:
		return "unknown"
	}
}

type AlertDescription uint8

const (
	AlertDescriptionCloseNotify            AlertDescription = 0
	AlertDescriptionUnexpectedMessage      AlertDescription = 10
	AlertDescriptionBadRecordMac           AlertDescription = 20
	AlertDescriptionDecryptionFailed       AlertDescription = 21
	AlertDescriptionRecordOverflow         AlertDescription = 22
	AlertDescriptionDecompressionFailure   AlertDescription = 30
	AlertDescriptionHandshakeFailure       AlertDescription = 40
	AlertDescriptionBadCertificate         AlertDescription = 42
	AlertDescriptionUnsupportedCertificate AlertDescription = 43
	AlertDescriptionCertificateRevoked     AlertDescription = 44
	AlertDescriptionCertificateExpired     AlertDescription = 45
	AlertDescriptionCertificateUnknown     AlertDescription = 46
	AlertDescriptionIllegalParameter       AlertDescription = 47
	AlertDescriptionUnknownCa              AlertDescription = 48
	AlertDescriptionAccessDenied           AlertDescription = 49
	AlertDescriptionDecodeError            AlertDescription = 50
	AlertDescriptionDecryptError           AlertDescription = 51
	AlertDescriptionProtocolVersion        AlertDescription = 70
	AlertDescriptionInsufficientSecurity   AlertDescription = 71
	AlertDescriptionInternalError          AlertDescription = 80
	AlertDescriptionUserCanceled           AlertDescription = 90
	AlertDescriptionUnsupportedSite2site   AlertDescription = 200
	AlertDescriptionNoArea                 AlertDescription = 201
	AlertDescriptionUnsupportedAreatype    AlertDescription = 202
	AlertDescriptionBadIbcparam            AlertDescription = 203
	AlertDescriptionUnsupportedIbcparam    AlertDescription = 204
	AlertDescriptionIdentityNeed           AlertDescription = 205
	AlertDescriptionMaximum                AlertDescription = 255
)

var _ = AlertDescriptionMaximum

func (d AlertDescription) String() string {
	switch d {
	case AlertDescriptionCloseNotify:
		return "CloseNotify"
	case AlertDescriptionUnexpectedMessage:
		return "UnexpectedMessage"
	case AlertDescriptionBadRecordMac:
		return "BadRecordMac"
	case AlertDescriptionDecryptionFailed:
		return "DecryptionFailed"
	case AlertDescriptionRecordOverflow:
		return "RecordOverflow"
	case AlertDescriptionDecompressionFailure:
		return "DecompressionFailure"
	case AlertDescriptionHandshakeFailure:
		return "HandshakeFailure"
	case AlertDescriptionBadCertificate:
		return "BadCertificate"
	case AlertDescriptionUnsupportedCertificate:
		return "UnsupportedCertificate"
	case AlertDescriptionCertificateRevoked:
		return "CertificateRevoked"
	case AlertDescriptionCertificateExpired:
		return "CertificateExpired"
	case AlertDescriptionCertificateUnknown:
		return "CertificateUnknown"
	case AlertDescriptionIllegalParameter:
		return "IllegalParameter"
	case AlertDescriptionUnknownCa:
		return "UnknownCa"
	case AlertDescriptionAccessDenied:
		return "AccessDenied"
	case AlertDescriptionDecodeError:
		return "DecodeError"
	case AlertDescriptionDecryptError:
		return "DecryptError"
	case AlertDescriptionProtocolVersion:
		return "ProtocolVersion"
	case AlertDescriptionInsufficientSecurity:
		return "InsufficientSecurity"
	case AlertDescriptionInternalError:
		return "InternalError"
	case AlertDescriptionUserCanceled:
		return "UserCanceled"
	case AlertDescriptionUnsupportedSite2site:
		return "UnsupportedSite2site"
	case AlertDescriptionNoArea:
		return "NoArea"
	case AlertDescriptionUnsupportedAreatype:
		return "UnsupportedAreatype"
	case AlertDescriptionBadIbcparam:
		return "BadIbcparam"
	case AlertDescriptionUnsupportedIbcparam:
		return "UnsupportedIbcparam"
	case AlertDescriptionIdentityNeed:
		return "IdentityNeed"
	default:
		return "unknown"
	}
}

// IsWarning 判断是否为警告。参考 GM/T 0024-2014 第 6.4.2.2 节 "表 1 错误报警表" 定义。
func (d AlertDescription) IsWarning() bool {
	switch d {
	case AlertDescriptionUserCanceled:
		return true
	}
	return false
}

// IsFatal 判断是否为致命错误。参考 GM/T 0024-2014 第 6.4.2.2 节 "表 1 错误报警表" 定义。
func (d AlertDescription) IsFatal() bool {
	switch d {
	case AlertDescriptionUnexpectedMessage,
		AlertDescriptionBadRecordMac,
		AlertDescriptionDecryptionFailed,
		AlertDescriptionRecordOverflow,
		AlertDescriptionDecompressionFailure,
		AlertDescriptionHandshakeFailure,
		AlertDescriptionIllegalParameter,
		AlertDescriptionUnknownCa,
		AlertDescriptionAccessDenied,
		AlertDescriptionDecodeError,
		AlertDescriptionProtocolVersion,
		AlertDescriptionInsufficientSecurity,
		AlertDescriptionInternalError,
		AlertDescriptionUnsupportedSite2site,
		AlertDescriptionBadIbcparam,
		AlertDescriptionUnsupportedIbcparam,
		AlertDescriptionIdentityNeed:
		return true
	}
	return false
}
