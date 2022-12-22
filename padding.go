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
	ANSIX_PADDING PaddingT = "ANSIX923"
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
// *	-update: 2022/12/22 09:37:01 ColeCai.
// *********************************************************************************************************************
func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return src, ErrorUnPadding
	}
	paddingSize := length - -int(src[length]-1)
	if paddingSize <= 0 {
		return src, ErrorUnPadding
	}
	return src[:paddingSize], nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/02 10:38:19 ColeCai.
// *	-update: 2022/12/21 09:56:54 ColeCai.
// *             PKCS5 padding length is 8 bytes
// *********************************************************************************************************************
func PKCS5Padding(src []byte) []byte {
	return PKCS7Padding(src, 8)
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
// *	-update: 2022/12/20 11:42:18 ColeCai.
// *********************************************************************************************************************
func ZerosPadding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	return append(src, bytes.Repeat([]byte{byte(0)}, padding)...)
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/03 10:05:30 ColeCai.
// *	-update: 2022/12/20 11:42:32 ColeCai.
// *********************************************************************************************************************
func ZerosUnPadding(src []byte) ([]byte, error) {
	return bytes.TrimFunc(src, func(r rune) bool {
		return r == rune(0)
	}), nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/22 09:29:27 ColeCai.
// *********************************************************************************************************************
func Ansix923Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	paddingText := append(bytes.Repeat([]byte{byte(0)}, paddingSize-1), byte(paddingSize))
	return append(src, paddingText...)
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/22 09:34:26 ColeCai.
// *********************************************************************************************************************
func Ansix923UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return src, ErrorUnPadding
	}
	paddingSize := length - -int(src[length]-1)
	if paddingSize <= 0 {
		return src, ErrorUnPadding
	}
	return src[:paddingSize], nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/04 10:31:39 ColeCai.
// *********************************************************************************************************************
func Padding(padding PaddingT, src []byte, blockSize int) []byte {
	switch padding {
	case PKCS5_PADDING:
		return PKCS5Padding(src)
	case PKCS7_PADDING:
		return PKCS7Padding(src, blockSize)
	case ZEROS_PADDING:
		return ZerosPadding(src, blockSize)
	}
	return src
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/04 10:34:16 ColeCai.
// *********************************************************************************************************************
func UnPadding(padding PaddingT, src []byte) ([]byte, error) {
	switch padding {
	case PKCS5_PADDING:
		return PKCS5UnPadding(src)
	case PKCS7_PADDING:
		return PKCS7UnPadding(src)
	case ZEROS_PADDING:
		return ZerosUnPadding(src)
	}
	return src, nil
}
