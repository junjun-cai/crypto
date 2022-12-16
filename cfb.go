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
	enStream cipher.Stream
	deStream cipher.Stream
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/10 10:43:51 ColeCai.
// *	-update: 2022/12/16 09:57:20 ColeCai.
// *             init encrypt and decrypt stream in CFBCipher construction stage.
// *********************************************************************************************************************
func NewCFBCipher(block cipher.Block, iv []byte) *CFBCipher {
	return &CFBCipher{
		enStream: cipher.NewCFBEncrypter(block, iv),
		deStream: cipher.NewCFBDecrypter(block, iv),
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
	c.enStream.XORKeyStream(encrypted, src)
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
	c.deStream.XORKeyStream(decrypted, src)
	return decrypted, nil
}
