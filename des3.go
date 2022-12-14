// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/12/05 9:48
// * File: des3.go
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
// *    -create: 2022/12/05 09:49:55 ColeCai.
// *********************************************************************************************************************
func New3DesCBCCryptor(desKey, iv []byte, padding padding) (ICryptor, error) {
	cipher, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	return NewCBCCipher(cipher, iv, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/06 09:57:12 ColeCai.
// *********************************************************************************************************************
func New3DesCFBCryptor(desKey, iv []byte) (ICryptor, error) {
	cipher, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	return NewCFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/07 09:38:04 ColeCai.
// *********************************************************************************************************************
func New3DesECBCryptor(desKey []byte, padding padding) (ICryptor, error) {
	cipher, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	return NewECBCipher(cipher, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/08 09:38:13 ColeCai.
// *********************************************************************************************************************
func New3DesOFBCryptor(desKey, iv []byte) (ICryptor, error) {
	cipher, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	return NewOFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/09 10:21:34 ColeCai.
// *********************************************************************************************************************
func New3DesCTRCryptor(desKey, iv []byte) (ICryptor, error) {
	cipher, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, err
	}
	return NewCTRCipher(cipher, iv), nil
}
