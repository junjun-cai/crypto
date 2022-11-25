// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/11/21 9:52
// * File: aes.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "crypto/aes"

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/21 09:53:18 ColeCai.
// *********************************************************************************************************************
func NewAesCBCCryptor(aesKey, iv []byte, padding PaddingT) (ICryptor, error) {
	cipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return NewCBCCipher(cipher, iv, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/22 09:58:58 ColeCai.
// *********************************************************************************************************************
func NewAesCFBCryptor(aesKey, iv []byte) (ICryptor, error) {
	cipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return NewCFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/23 09:44:03 ColeCai.
// *********************************************************************************************************************
func NewAesECBCryptor(aesKey []byte, padding PaddingT) (ICryptor, error) {
	cipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return NewECBCipher(cipher, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/24 10:35:27 ColeCai.
// *********************************************************************************************************************
func NewAesOFBCryptor(aesKey, iv []byte) (ICryptor, error) {
	cipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return NewOFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/25 09:42:57 ColeCai.
// *********************************************************************************************************************
func NewAesCTRCryptor(aesKey, iv []byte) (ICryptor, error) {
	cipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return NewCTRCipher(cipher, iv), nil
}
