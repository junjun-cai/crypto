// *********************************************************************************************************************
// ***                                        CONFIDENTIAL --- CUSTOM STUDIOS                                        ***
// *********************************************************************************************************************
// * Auth: ColeCai                                                                                                     *
// * Date: 2023/10/30 12:46:08                                                                                         *
// * Proj: crypto                                                                                                      *
// * Pack: crypto                                                                                                      *
// * File: base_test.go                                                                                                *
// *-------------------------------------------------------------------------------------------------------------------*
// * Overviews:                                                                                                        *
// *-------------------------------------------------------------------------------------------------------------------*
// * Functions:                                                                                                        *
// * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - *

package crypto

import (
	"fmt"
	"github.com/golang-module/dongle"
	"github.com/golang-module/dongle/morse"
	"github.com/jamescun/basex"
	"testing"
)

func TestFDongle(t *testing.T) {
	b58 := dongle.Encode.FromString("Fafsgfdsn").ByBase45().ToString()
	fmt.Println("b58:", b58)
	l := len([]byte("Fafsgfdsn"))
	tl := int(float32(l) * 1.37)
	fmt.Println("tl:", tl)
	fmt.Println("bl:", len([]byte(b58)))
	//dongle.Encrypt.FromString("Fafsgfdsn").ByAes()
}

func TestC(t *testing.T) {
	a := basex.Base8
	src := []byte("foo")
	dst := make([]byte, a.EncodedLen(len(src)))
	a.Encode(dst, src)
	fmt.Println(string(dst))
	morse.Encode()
}
