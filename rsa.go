// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/12/14 9:53
// * File: rsa.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
)

type RSACryptor struct {
	pubKey *rsa.PublicKey
	priKey *rsa.PrivateKey
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/14 09:54:41 ColeCai.
// *********************************************************************************************************************
func (r *RSACryptor) decodePubKey(pubKey []byte) error {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return errors.New("invalid rsa public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	r.pubKey = pub.(*rsa.PublicKey)
	return nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/14 09:58:20 ColeCai.
// *********************************************************************************************************************
func (r *RSACryptor) decodePriKey(priKey []byte) error {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return errors.New("invalid rsa private key")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	r.priKey = pri
	return nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/14 10:01:17 ColeCai.
// *********************************************************************************************************************
func NewRSACryptor(pubKey, priKey []byte) (*RSACryptor, error) {
	r := &RSACryptor{}
	if err := r.decodePubKey(pubKey); err != nil {
		return nil, err
	}
	if err := r.decodePriKey(priKey); err != nil {
		return nil, err
	}
	return r, nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/14 10:02:41 ColeCai.
// *********************************************************************************************************************
func (r *RSACryptor) Encrypt(src []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, r.pubKey, src)
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/14 10:03:45 ColeCai.
// *********************************************************************************************************************
func (r *RSACryptor) Decrypt(src []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, r.priKey, src)
}
