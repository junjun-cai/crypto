// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/11/07 10:19
// * File: cbc.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "crypto/cipher"

type CBCCipher struct {
	block   cipher.Block
	iv      []byte
	padding PaddingT
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/07 10:45:43 ColeCai.
// *********************************************************************************************************************
func NewCBCCipher(block cipher.Block, iv []byte, padding PaddingT) *CBCCipher {
	return &CBCCipher{
		block:   block,
		iv:      iv,
		padding: padding,
	}
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/07 10:47:24 ColeCai.
// *********************************************************************************************************************
func (c *CBCCipher) Encrypt(src []byte) ([]byte, error) {
	padding := Padding(c.padding, src, c.block.BlockSize())
	encrypted := make([]byte, len(padding))
	cbc := cipher.NewCBCEncrypter(c.block, c.iv)
	cbc.CryptBlocks(encrypted, padding)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/07 10:50:10 ColeCai.
// *********************************************************************************************************************
func (c *CBCCipher) Decrypt(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	cbc := cipher.NewCBCDecrypter(c.block, c.iv)
	cbc.CryptBlocks(decrypted, src)
	return UnPadding(c.padding, decrypted)
}
