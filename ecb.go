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
	padding PaddingT
	enBlock cipher.BlockMode
	deBlock cipher.BlockMode
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/17 09:42:17 ColeCai.
// *	-update: 2022/12/20 09:36:13 ColeCai.
// *			 init encrypt and decrypt block in ECBCipher construction stage.
// *********************************************************************************************************************
func NewECBCipher(block cipher.Block, padding PaddingT) *ECBCipher {
	return &ECBCipher{
		padding: padding,
		enBlock: newECBEncrypter(block),
		deBlock: newECBDecrypter(block),
	}
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/17 09:43:14 ColeCai.
// *	-update: 2022/12/20 09:38:29 ColeCai.
// *********************************************************************************************************************
func (e *ECBCipher) Encrypt(src []byte) ([]byte, error) {
	src = Padding(e.padding, src, e.enBlock.BlockSize())
	encrypted := make([]byte, len(src))
	e.enBlock.CryptBlocks(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/17 09:45:27 ColeCai.
// *	-update: 2022/12/20 09:39:30 ColeCai.
// *********************************************************************************************************************
func (e *ECBCipher) Decrypt(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	e.deBlock.CryptBlocks(decrypted, src)
	return UnPadding(e.padding, decrypted)
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
// *	-update: 2022/12/20 09:34:34 ColeCai.
// *********************************************************************************************************************
func newECBEncrypter(b cipher.Block) cipher.BlockMode {
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
// *	-update: 2022/12/20 09:34:50 ColeCai.
// *********************************************************************************************************************
func newECBDecrypter(b cipher.Block) cipher.BlockMode {
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
