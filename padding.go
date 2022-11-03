// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/11/02 10:30
// * File: padding.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"bytes"
	"github.com/pkg/errors"
)

var ErrorUnPadding = errors.New("UnPadding Error.")

type PaddingT string

const (
	PKCS5_PADDING PaddingT = "PKCS5"
	PKCS7_PADDING PaddingT = "PKCS7"
	ZEROS_PADDING PaddingT = "ZEROS"
)

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/02 10:34:44 ColeCai.
// *********************************************************************************************************************
func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/02 10:36:38 ColeCai.
// *********************************************************************************************************************
func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return src, ErrorUnPadding
	}
	unPadding := int(src[length-1])
	if length < unPadding {
		return src, ErrorUnPadding
	}
	return src[:(length - unPadding)], nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/02 10:38:19 ColeCai.
// *********************************************************************************************************************
func PKCS5Padding(src []byte, blockSize int) []byte {
	return PKCS7Padding(src, blockSize)
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/02 10:39:13 ColeCai.
// *********************************************************************************************************************
func PKCS5UnPadding(src []byte) ([]byte, error) {
	return PKCS7UnPadding(src)
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/03 10:03:49 ColeCai.
// *********************************************************************************************************************
func ZerosPadding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	if padding == 0 {
		return src
	}
	return append(src, bytes.Repeat([]byte{byte(0)}, padding)...)
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/03 10:05:30 ColeCai.
// *********************************************************************************************************************
func ZerosUnPadding(src []byte) ([]byte, error) {
	for i := len(src) - 1; ; i-- {
		if src[i] != 0 {
			return src[:i+1], nil
		}
	}
}
