// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/11/11 14:19
// * File: ctr.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "crypto/cipher"

type CTRCipher struct {
	ctrStream cipher.Stream
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/11 14:20:08 ColeCai.
// *	-update: 2022/12/19 14:08:54 ColeCai.
// *             init CTR stream in CTRCipher construction stage.
// *********************************************************************************************************************
func NewCTRCipher(block cipher.Block, iv []byte) *CTRCipher {
	return &CTRCipher{ctrStream: cipher.NewCTR(block, iv)}
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/11 14:20:59 ColeCai.
// *	-update: 2022/12/19 14:09:44 ColeCai.
// *********************************************************************************************************************
func (c *CTRCipher) Encrypt(src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	c.ctrStream.XORKeyStream(dst, src)
	return dst, nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/11 14:22:40 ColeCai.
// *	-update: 2022/12/19 14:10:23 ColeCai.
// *********************************************************************************************************************
func (c *CTRCipher) Decrypt(src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	c.ctrStream.XORKeyStream(dst, src)
	return dst, nil
}
