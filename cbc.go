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
	padding padding
	enBlock cipher.BlockMode
	deBlock cipher.BlockMode
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/07 10:45:43 ColeCai.
// *	-update: 2022/12/15 09:51:03 ColeCai.
// *			 init encrypt and decrypt block in CBCCipher construction stage.
// *********************************************************************************************************************
func NewCBCCipher(block cipher.Block, iv []byte, padding padding) *CBCCipher {
	return &CBCCipher{
		padding: padding,
		enBlock: cipher.NewCBCEncrypter(block, iv),
		deBlock: cipher.NewCBCDecrypter(block, iv),
	}
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/07 10:47:24 ColeCai.
// *	-update: 2022/12/15 09:54:08 ColeCai.
// *	-update: 2022/12/24 17:50:58 ColeCai.
// *********************************************************************************************************************
func (c *CBCCipher) Encrypt(src []byte) ([]byte, error) {
	padding, err := Padding(c.padding, src, c.enBlock.BlockSize())
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(padding))
	c.enBlock.CryptBlocks(encrypted, padding)
	return encrypted, nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/07 10:50:10 ColeCai.
// *	-update: 2022/12/15 10:00:03 ColeCai.
// *********************************************************************************************************************
func (c *CBCCipher) Decrypt(src []byte) ([]byte, error) {
	decrypted := make([]byte, len(src))
	c.deBlock.CryptBlocks(decrypted, src)
	return UnPadding(c.padding, decrypted)
}
