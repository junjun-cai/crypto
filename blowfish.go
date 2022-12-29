// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/12/25 17:21
// * File: blowfish.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "golang.org/x/crypto/blowfish"

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/25 17:22:39 ColeCai.
// ***********************************************************************************************
func NewBlowfishCBCCryptor(blowKey, iv []byte, padding padding) (ICryptor, error) {
	cipher, err := blowfish.NewCipher(blowKey)
	if err != nil {
		return nil, err
	}
	return NewCBCCipher(cipher, iv, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/26 10:08:40 ColeCai.
// *********************************************************************************************************************
func NewBlowfishCFBCryptor(blowKey, iv []byte) (ICryptor, error) {
	cipher, err := blowfish.NewCipher(blowKey)
	if err != nil {
		return nil, err
	}
	return NewCFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/27 09:40:54 ColeCai.
// *********************************************************************************************************************
func NewBlowfishECBCryptor(blowKey []byte, padding padding) (ICryptor, error) {
	cipher, err := blowfish.NewCipher(blowKey)
	if err != nil {
		return nil, err
	}
	return NewECBCipher(cipher, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/28 09:45:50 ColeCai.
// *********************************************************************************************************************
func NewBlowfishOFBCryptor(blowKey, iv []byte) (ICryptor, error) {
	cipher, err := blowfish.NewCipher(blowKey)
	if err != nil {
		return nil, err
	}
	return NewOFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/29 09:45:22 ColeCai.
// *********************************************************************************************************************
func NewBlowfishCTRCryptor(blowKey, iv []byte) (ICryptor, error) {
	cipher, err := blowfish.NewCipher(blowKey)
	if err != nil {
		return nil, err
	}
	return NewCTRCipher(cipher, iv), nil
}
