// *********************************************************************************************************************
// ***                                          G O L A N D   S T U D I O S                                          ***
// *********************************************************************************************************************
// * Auth: ColeCai
// * Date: 2022/12/12 9:43
// * File: dic.go
// * Proj: crypto
// * Pack: crypto
// * Ides: GoLand
// *--------------------------------------------------------------------------------------------------------------------
// * Functions:
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

package crypto

type DICCryptor struct {
	encryptBytes []byte
	decryptBytes []byte
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/12 09:45:05 ColeCai.
// *********************************************************************************************************************
func NewDICEncryptor(enBytes, deBytes []byte) (ICryptor, error) {
	return &DICCryptor{encryptBytes: enBytes, decryptBytes: deBytes}, nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/12 09:46:55 ColeCai.
// *********************************************************************************************************************
func (d *DICCryptor) Encrypt(data []byte) ([]byte, error) {
	enBuf := make([]byte, len(data))
	for idx, v := range data {
		enBuf[idx] = d.encryptBytes[v]
	}
	return enBuf, nil
}

// *********************************************************************************************************************
// * SUMMARY:
// * WARNING:
// * HISTORY:
// *    -create: 2022/12/12 09:48:06 ColeCai.
// *********************************************************************************************************************
func (d *DICCryptor) Decrypt(data []byte) ([]byte, error) {
	deBuffer := make([]byte, len(data))
	for idx, v := range data {
		deBuffer[idx] = d.decryptBytes[v]
	}
	return deBuffer, nil
}
