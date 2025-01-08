package gmtls_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm3"

	"github.com/nnnewb/gmtls"
)

func Test_PHash(t *testing.T) {
	type args struct {
		result []byte
		secret []byte
		seed   []byte
		hash   func() hash.Hash
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "simple sm3",
			args: args{
				result: make([]byte, 32),
				secret: []byte("secret"),
				seed:   []byte("seed"),
				hash:   sm3.New,
			},
		},
		{
			name: "simple sha1",
			args: args{
				result: make([]byte, 32),
				secret: []byte("secret"),
				seed:   []byte("seed"),
				hash:   sha1.New,
			},
		},
		{
			name: "simple sha1 unaligned",
			args: args{
				result: make([]byte, 35),
				secret: []byte("secret"),
				seed:   []byte("seed"),
				hash:   sha1.New,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gmtls.PHash(tt.args.result, tt.args.secret, tt.args.seed, tt.args.hash)
			assert.NotEqual(t, make([]byte, 32), tt.args.result)
			t.Logf("gmtls.PHash result: %s", hex.EncodeToString(tt.args.result))
		})
	}
}

func Benchmark_PHash(b *testing.B) {
	result := make([]byte, 512)
	secret := []byte("secret")
	seed := []byte("seed")
	b.Run("PHash with SM3", func(b *testing.B) {
		h := sm3.New
		for i := 0; i < b.N; i++ {
			gmtls.PHash(result, secret, seed, h)
		}
	})

	b.Run("PHash with sha256", func(b *testing.B) {
		h := sha256.New
		for i := 0; i < b.N; i++ {
			gmtls.PHash(result, secret, seed, h)
		}
	})

	b.Run("PHashSM3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gmtls.PHashSM3(result, secret, seed)
		}
	})
}

func BenchmarkHashAlgorithm(b *testing.B) {
	var items = []struct {
		name string
		a    []byte
		h    hash.Hash
	}{
		{
			name: "sm3",
			a:    make([]byte, 32),
			h:    sm3.New(),
		},
		{
			name: "sha1",
			a:    make([]byte, sha1.New().Size()),
			h:    sha1.New(),
		},
		{
			name: "sha256",
			a:    make([]byte, sha256.New().Size()),
			h:    sha256.New(),
		},
		{
			name: "sha512",
			a:    make([]byte, sha512.New().Size()),
			h:    sha512.New(),
		},
	}
	for _, item := range items {
		b.Run(item.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				item.h.Reset()
				item.h.Write([]byte("secret"))
				item.h.Write([]byte("seed"))
				item.h.Sum(item.a[:0])
			}
		})
	}
}
