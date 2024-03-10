// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/26 20:41:58                                                                                         *
// * Proj: crypto                                                                                                      *
// * Pack: crypto                                                                                                      *
// * File: xts.go                                                                                                      *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package crypto

import (
	"crypto/cipher"
	"golang.org/x/crypto/xts"
)

type XTSCryptor struct {
	cipher *xts.Cipher
	sector uint64
}

func NewXTSCryptor(cipherFunc func([]byte) (cipher.Block, error), key []byte, sector uint64) (ICryptor, error) {
	c, err := xts.NewCipher(cipherFunc, key)
	if err != nil {
		return nil, err
	}
	return &XTSCryptor{cipher: c, sector: sector}, nil
}

func (X *XTSCryptor) Encrypt(src []byte) ([]byte, error) {
	cipherText := make([]byte, len(src))
	X.cipher.Encrypt(cipherText, src, X.sector)
	return cipherText, nil
}

func (X *XTSCryptor) Decrypt(src []byte) ([]byte, error) {
	plainText := make([]byte, len(src))
	X.cipher.Decrypt(plainText, src, X.sector)
	return plainText, nil
}
