package common

import (
	"crypto/hmac"
	"hash"

	"github.com/tjfoc/gmsm/sm3"
)

// PHash implements the P_hash function, as defined in RFC 4346, section 5.
//
// quote here:
//
//	In order to make the PRF as secure as possible, it uses two hash
//	algorithms in a way that should guarantee its security if either
//	algorithm remains secure.
//
//	First, we define a data expansion function, P_hash(secret, data) that
//	uses a single hash function to expand a secret and seed into an
//	arbitrary quantity of output:
//
//		P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//		HMAC_hash(secret, A(2) + seed) +
//		HMAC_hash(secret, A(3) + seed) + ...
//
//	Where + indicates concatenation.
//
//	A() is defined as:
//
//		A(0) = seed
//		A(i) = HMAC_hash(secret, A(i-1))
//
//	P_hash can be iterated as many times as is necessary to produce the
//	required quantity of data.  For example, if P_SHA-1 is being used to
//	create 64 bytes of data, it will have to be iterated 4 times (through
//	A(4)), creating 80 bytes of output data; the last 16 bytes of the
//	final iteration will then be discarded, leaving 64 bytes of output
//	data.
func PHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		todo := len(b)
		if j+todo > len(result) {
			todo = len(result) - j
		}
		copy(result[j:j+todo], b)
		j += todo

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// PHashSM3 implements the optimized zero allocation P_SM3 function, as defined in GM/T 0024-2014, section 5.
func PHashSM3(result, secret, seed []byte) {
	var a [32]byte // round output, length equals to sm3.Size
	h := hmac.New(sm3.New, secret)
	h.Write(seed)
	h.Sum(a[:0]) // let a = A(1)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a[:])
		h.Write(seed)
		h.Sum(a[:0])

		copy(result[j:], a[:])

		if j+len(a) >= len(result) {
			break
		}

		j += len(a)

		h.Reset()
		h.Write(a[:])
		h.Sum(a[:0])
	}
}

// PRF implements the pseudo random function PRF, as defined in GM/T 0024-2014, section 5.
//
// quote here:
//
//	PRF 的计算方法如下
//
//		PRF(secret, label, seed) = P_SM3(secret, label + seed)
func PRF(result, secret, label, seed []byte) {
	var concat = make([]byte, len(label)+len(seed))
	copy(concat, label)
	copy(concat[len(label):], seed)
	PHashSM3(result, secret, concat)
}
