package handshaking

import (
	"io"

	"github.com/tjfoc/gmsm/sm2"
)

// ECCKeyExchangeSignature 当秘钥交换算法是 ECC 时，生成 key exchange message 的内容。
// 定义于 GM/T 0024-2014 第 6.4.4.3 节，signed_params。使用 SM2 算法签名。
//
// 参数 result 是最终输出的 signed_params。调用方应保证长度充足。
//
// 参数 clientRandom、serverRandom、certificate 为待签名的内容。
//
// 参数 key 是签名使用的私钥。
//
// 参数 rand 是签名所需的随机数发生器，一般可以用 crypto/rand。
//
// 参考实现：https://github.com/guanzhi/GmSSL/blob/d655c06b3a6b0fe8cff900f293bf0e5aac6eb0a2/src/tlcp.c#L721-L735
func ECCKeyExchangeSignature(clientRandom, serverRandom, certificate []byte, key *sm2.PrivateKey, r io.Reader) ([]byte, error) {
	msg := make([]byte, len(clientRandom)+len(serverRandom)+len(certificate))
	copy(msg, clientRandom)
	copy(msg[len(clientRandom):], serverRandom)
	copy(msg[len(clientRandom)+len(serverRandom):], certificate)
	return key.Sign(r, msg, nil)
}

// ECCKeyExchangeGeneratePreMasterSecret 当秘钥交换算法是 ECC 时，生成未加密的 pre_master_secret。
func ECCKeyExchangeGeneratePreMasterSecret(key *sm2.PublicKey, r io.Reader) ([]byte, error) {
	ret := make([]byte, 48)
	_, err := io.ReadFull(r, ret)
	if err != nil {
		return nil, err
	}

	return ret, nil
}
