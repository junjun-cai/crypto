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

type padding string

const (
	No       padding = "no"
	PKCS5    padding = "PKCS5"
	PKCS7    padding = "PKCS7"
	ZERO     padding = "ZERO"
	ANSIX923 padding = "ANSIX923"
	ISO97971 padding = "ISO97971"
	ISO10126 padding = "ISO10126"
)

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/02 10:34:44 ColeCai.
// *********************************************************************************************************************
func PKCS7Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(src, paddingText...)
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
	paddingSize := blockSize - len(src)%blockSize
	return append(src, bytes.Repeat([]byte{byte(0)}, paddingSize)...)
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
// *    -create: 2022/12/23 09:37:50 ColeCai.
// *********************************************************************************************************************
func Iso97971Padding(src []byte, blockSize int) []byte {
	return ZerosPadding(append(src, 0x80), blockSize)
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/23 09:39:03 ColeCai.
// *********************************************************************************************************************
func Iso97971UnPadding(src []byte) ([]byte, error) {
	dst, err := ZerosUnPadding(src)
	if err != nil {
		return nil, err
	}
	length := len(dst)
	if length <= 0 {
		return nil, ErrorUnPadding
	}
	return dst[:length-1], nil
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/24 17:27:56 ColeCai.
// ***********************************************************************************************
func Iso10126Padding(src []byte, blockSize int) []byte {
	paddingSize := blockSize - len(src)%blockSize
	randText := RandNBytes(blockSize - 1)
	paddingText := append(randText, byte(paddingSize))
	return append(src, paddingText...)
}

// ***********************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/24 17:30:29 ColeCai.
// ***********************************************************************************************
func Iso10126UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	if length <= 0 {
		return src, ErrorUnPadding
	}
	paddingSize := int(src[length-1])
	if length <= paddingSize {
		return src, ErrorUnPadding
	}
	return src[0 : length-paddingSize], nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/04 10:31:39 ColeCai.
// *	-update: 2022/12/24 17:34:46 ColeCai.
// *********************************************************************************************************************
func Padding(padding padding, src []byte, blockSize int) ([]byte, error) {
	switch padding {
	case No:
		return src, nil
	case PKCS5:
		return PKCS5Padding(src), nil
	case PKCS7:
		return PKCS7Padding(src, blockSize), nil
	case ZERO:
		return ZerosPadding(src, blockSize), nil
	case ANSIX923:
		return Ansix923Padding(src, blockSize), nil
	case ISO97971:
		return Iso97971Padding(src, blockSize), nil
	case ISO10126:
		return Iso10126Padding(src, blockSize), nil
	default:
		return nil, errors.New("unsupported padding type")
	}
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/11/04 10:34:16 ColeCai.
// *	-update: 2022/12/24 17:35:53 ColeCai.
// *********************************************************************************************************************
func UnPadding(padding padding, src []byte) ([]byte, error) {
	switch padding {
	case No:
		return src, nil
	case PKCS5:
		return PKCS5UnPadding(src)
	case PKCS7:
		return PKCS7UnPadding(src)
	case ZERO:
		return ZerosUnPadding(src)
	case ANSIX923:
		return Ansix923UnPadding(src)
	case ISO97971:
		return Iso97971UnPadding(src)
	case ISO10126:
		return Iso10126UnPadding(src)
	default:
		return src, nil
	}
}
