// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/11/28 9:37
// * File: des.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "crypto/des"

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/28 09:38:33 ColeCai.
// *********************************************************************************************************************
func NewDesCBCCryptor(desKey, iv []byte, padding PaddingT) (ICryptor, error) {
	cipher, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return NewCBCCipher(cipher, iv, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/29 10:49:28 ColeCai.
// *********************************************************************************************************************
func NewDesCFBCryptor(desKey, iv []byte) (ICryptor, error) {
	cipher, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return NewCFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/30 10:05:29 ColeCai.
// *********************************************************************************************************************
func NewDesECBCryptor(desKey []byte, padding PaddingT) (ICryptor, error) {
	cipher, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return NewECBCipher(cipher, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/01 09:45:32 ColeCai.
// *********************************************************************************************************************
func NewDesOFBCryptor(desKey, iv []byte) (ICryptor, error) {
	cipher, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}
	return NewOFBCipher(cipher, iv), nil
}
