// vim: tabstop=2 shiftwidth=2

package main

import (
	"crypto/aes"
	"crypto/cipher"
)

// EncryptAESCFB performs AES CFB encryption on a byte slice.  For input, it
// expects to receive a reference to a prefedined slice (cipherbytes), a slice
// to be encrypted (plainbytes), an AES key of size 16, 24 or 32 and an
// initialization vector (iv).
func EncryptAESCFB(cipherbytes []byte, plainbytes []byte, key []byte, iv []byte) error {
	aesBlockEncrypter, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(cipherbytes, plainbytes)
	return nil
}

// DecryptAESCFB performs AES CFB decryption on a byte slice,  It takes four
// input parameters: A predefined input slice where the decrypted output will
// be written (plainbytes).  A slice containing the encrypted payload
// (cipehrbytes).  An AES key (key) and IV (iv).
func DecryptAESCFB(plainbytes []byte, cipherbytes []byte, key []byte, iv []byte) error {
	aesBlockDecrypter, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(plainbytes, cipherbytes)
	return nil
}

/*
func main() {
	var key = []byte("01234567890123456789012345678901")
	var iv = []byte("0123456789012345")
	var msg = "message"
	var err error

	// Encrypt
	encrypted := make([]byte, len(msg))
	err = EncryptAESCFB(encrypted, []byte(msg), key, iv)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypting %v %s -> %v\n", []byte(msg), msg, encrypted)

	// Decrypt
	decrypted := make([]byte, len(msg))
	err = DecryptAESCFB(decrypted, encrypted, []byte(key), iv)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypting %v -> %v %s\n", encrypted, decrypted, decrypted)
}
*/
