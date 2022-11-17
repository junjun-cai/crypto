// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/11/15 12:10
// * File: ecb.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "crypto/cipher"

type ECBCipher struct {
	block   cipher.Block
	padding PaddingT
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/17 09:42:17 ColeCai.
// *********************************************************************************************************************
func NewECBCipher(block cipher.Block, padding PaddingT) *ECBCipher {
	return &ECBCipher{
		block:   block,
		padding: padding,
	}
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/17 09:43:14 ColeCai.
// *********************************************************************************************************************
func (e *ECBCipher) Encrypt(src []byte) ([]byte, error) {
	src = Padding(e.padding, src, e.block.BlockSize())
	encrypted := make([]byte, len(src))
	ecb := NewECBEncrypter(e.block)
	ecb.CryptBlocks(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/17 09:45:27 ColeCai.
// *********************************************************************************************************************
func (e *ECBCipher) Decrypt(src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	ecb := NewECBDecrypter(e.block)
	ecb.CryptBlocks(dst, src)
	return UnPadding(e.padding, dst)
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/15 12:11:48 ColeCai.
// *********************************************************************************************************************
func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/15 12:13:09 ColeCai.
// *********************************************************************************************************************
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/15 12:15:58 ColeCai.
// *********************************************************************************************************************
func (e *ecbEncrypter) BlockSize() int { return e.blockSize }

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/15 12:16:31 ColeCai.
// *********************************************************************************************************************
func (e *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/ecb: input not full blocks.")
	}
	if len(dst) < len(src) {
		panic("crypto/ecb: output smaller than input.")
	}
	for len(src) > 0 {
		e.b.Encrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}

type ecbDecrypter ecb

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/16 10:06:31 ColeCai.
// *********************************************************************************************************************
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/16 10:07:39 ColeCai.
// ********************************************************************************************************************
func (e *ecbDecrypter) BlockSize() int { return e.blockSize }

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/16 10:08:17 ColeCai.
// *********************************************************************************************************************
func (e *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%e.blockSize != 0 {
		panic("crypto/ecb: input not full blocks.")
	}
	if len(dst) < len(src) {
		panic("crypto/ecb: output smaller than input.")
	}
	for len(src) > 0 {
		e.b.Decrypt(dst, src[:e.blockSize])
		src = src[e.blockSize:]
		dst = dst[e.blockSize:]
	}
}
