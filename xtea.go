// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2023/01/06 09:42
// * File: xtea.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"golang.org/x/crypto/xtea"
)

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2023/01/06 09:43:20 ColeCai.
// *********************************************************************************************************************
func NewXteaCBCCryptor(xteaKey, iv []byte, padding padding) (ICryptor, error) {
	cipher, err := xtea.NewCipher(xteaKey)
	if err != nil {
		return nil, err
	}
	return NewCBCCipher(cipher, iv, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2023/01/09 09:46:03 ColeCai.
// *********************************************************************************************************************
func NewXteaCFBCryptor(xteaKey, iv []byte) (ICryptor, error) {
	cipher, err := xtea.NewCipher(xteaKey)
	if err != nil {
		return nil, err
	}
	return NewCFBCipher(cipher, iv), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2023/01/10 09:34:34 ColeCai.
// *********************************************************************************************************************
func NewXteaECBCryptor(xteaKey []byte, padding padding) (ICryptor, error) {
	cipher, err := xtea.NewCipher(xteaKey)
	if err != nil {
		return nil, err
	}
	return NewECBCipher(cipher, padding), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2023/01/11 09:42:59 ColeCai.
// *********************************************************************************************************************
func NewXteaOFBCryptor(xteaKey, iv []byte) (ICryptor, error) {
	cipher, err := xtea.NewCipher(xteaKey)
	if err != nil {
		return nil, err
	}
	return NewOFBCipher(cipher, iv), nil
}
