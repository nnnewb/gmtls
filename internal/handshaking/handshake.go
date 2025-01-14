package handshaking

type Uint24 uint32

type Handshake struct {
	MessageType HandshakeType
	Length      Uint24
	Body        []byte
}

type HandshakeType uint8

const (
	HandshakeTypeClientHello        HandshakeType = 1
	HandshakeTypeServerHello        HandshakeType = 2
	HandshakeTypeCertificate        HandshakeType = 11
	HandshakeTypeServerKeyExchange  HandshakeType = 12
	HandshakeTypeCertificateRequest HandshakeType = 13
	HandshakeTypeServerHelloDone    HandshakeType = 14
	HandshakeTypeCertificateVerify  HandshakeType = 15
	HandshakeTypeClientKeyExchange  HandshakeType = 16
	HandshakeTypeFinished           HandshakeType = 20
	HandshakeTypeMaximum            HandshakeType = 255
)

var _ = HandshakeTypeMaximum

func (h HandshakeType) String() string {
	switch h {
	case HandshakeTypeClientHello:
		return "client_hello"
	case HandshakeTypeServerHello:
		return "server_hello"
	case HandshakeTypeCertificate:
		return "certificate"
	case HandshakeTypeServerKeyExchange:
		return "server_key_exchange"
	case HandshakeTypeCertificateRequest:
		return "certificate_request"
	case HandshakeTypeServerHelloDone:
		return "server_hello_done"
	case HandshakeTypeCertificateVerify:
		return "certificate_verify"
	case HandshakeTypeClientKeyExchange:
		return "client_key_exchange"
	case HandshakeTypeFinished:
		return "finished"
	default:
		return "unknown"
	}
}
