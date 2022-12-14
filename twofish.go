// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/12/30 09:44:56
// * File: twofish.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import "golang.org/x/crypto/twofish"

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/30 09:45:34 ColeCai.
// *********************************************************************************************************************
func NewTwofishCBCCryptor(twoKey, iv []byte, padding padding) (ICryptor, error) {
	cipher, err := twofish.NewCipher(twoKey)
	if err != nil {
		return nil, err
	}
	return NewCBCCipher(cipher, iv, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/31 23:14:04 ColeCai.
// *********************************************************************************************************************
func NewTwofishCFBCryptor(twoKey, iv []byte) (ICryptor, error) {
	cipher, err := twofish.NewCipher(twoKey)
	if err != nil {
		return nil, err
	}
	return NewCFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2023/01/03 09:48:52 ColeCai.
// *********************************************************************************************************************
func NewTwofishECBCryptor(twoKey []byte, padding padding) (ICryptor, error) {
	cipher, err := twofish.NewCipher(twoKey)
	if err != nil {
		return nil, err
	}
	return NewECBCipher(cipher, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2023/01/04 09:44:11 ColeCai.
// *********************************************************************************************************************
func NewTwofishOFBCryptor(twoKey, iv []byte) (ICryptor, error) {
	cipher, err := twofish.NewCipher(twoKey)
	if err != nil {
		return nil, err
	}
	return NewOFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2023/01/05 09:33:00 ColeCai.
// *********************************************************************************************************************
func NewTwofishCTRCryptor(twoKey, iv []byte) (ICryptor, error) {
	cipher, err := twofish.NewCipher(twoKey)
	if err != nil {
		return nil, err
	}
	return NewCTRCipher(cipher, iv), nil
}
