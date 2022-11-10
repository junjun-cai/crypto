// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/11/10 10:42
// * File: cfb.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "crypto/cipher"

type CFBCipher struct {
	block cipher.Block
	iv    []byte
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/10 10:43:51 ColeCai.
// *********************************************************************************************************************
func NewCFBCipher(block cipher.Block, iv []byte) *CFBCipher {
	return &CFBCipher{
		block: block,
		iv:    iv,
	}
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/10 10:45:10 ColeCai.
// *********************************************************************************************************************
func (c *CFBCipher) Encrypt(src []byte) ([]byte, error) {
	encrypted := make([]byte, len(src))
	cfb := cipher.NewCFBEncrypter(c.block, c.iv)
	cfb.XORKeyStream(encrypted, src)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/10 10:59:16 ColeCai.
// *********************************************************************************************************************
func (c *CFBCipher) Decrypt(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	cfb := cipher.NewCFBDecrypter(c.block, c.iv)
	cfb.XORKeyStream(decrypted, src)
	return decrypted, nil
}
