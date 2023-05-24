//**********************************************************************************************************************
//@Auth:蔡君君
//@Date:2022/12/26 14:37:13
//@File:aaes.go
//@Pack:crypto
//@Proj:crypto
//@Ides:GoLand
//@Desc:
//**********************************************************************************************************************

package crypto

import (
	"crypto/aes"
	"github.com/pkg/errors"
)

type Mode string

const (
	CBC Mode = "CBC"
	CFB Mode = "CFB"
	OFB Mode = "OFB"
	ECB Mode = "ECB"
	CTR Mode = "CTR"
)

func NewAesCryptor(aesKey []byte, mode Mode, padding padding, iv []byte) (ICryptor, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	switch mode {
	case CBC:
		return NewCFBCipher(block, iv), nil
	case CFB:
		return NewCFBCipher(block, iv), nil
	case OFB:
		return NewOFBCipher(block, iv), nil
	case ECB:
		return NewECBCipher(block, padding), nil
	case CTR:
		return NewCTRCipher(block, iv), nil
	default:
		return nil, errors.New("error mode.")
	}
}
