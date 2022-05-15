package cryptutils

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	mrand "math/rand"
	"os"
	"unsafe"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

func RandString(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, mrand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = mrand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

func AESEncryptMessage(key []byte, message string) (string, bool) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", false
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), true
}

func AESDecryptMessage(key []byte, message string) (string, bool) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", false
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}

	if len(cipherText) < aes.BlockSize {
		return "", false
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), true
}

func RSAGenerateKeys(keysz int) (*rsa.PrivateKey, *rsa.PublicKey) {

	PrivateKey, err := rsa.GenerateKey(rand.Reader, keysz)
	if err != nil {
		return nil, nil
	}
	return PrivateKey, &PrivateKey.PublicKey
}

func RSASavePrvKeyToPEM(key *rsa.PrivateKey, filepath string, pass string) bool {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if pass != "" {
		var err error
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(pass), x509.PEMCipherAES256)
		if err != nil {
			return false
		}
	}
	pemPrivateFile, err := os.Create(filepath)
	err = pem.Encode(pemPrivateFile, block)
	if err != nil {
		return false
	}
	pemPrivateFile.Close()
	return true
}

func RSASavePubKeyToPEM(key *rsa.PublicKey, filepath string, pass string) bool {

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(key),
	}
	if pass != "" {
		var err error
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(pass), x509.PEMCipherAES256)
		if err != nil {
			return false
		}
	}
	pemPublicFile, err := os.Create(filepath)
	err = pem.Encode(pemPublicFile, block)
	if err != nil {
		return false
	}
	pemPublicFile.Close()
	return true
}

func RSAEncrypt(key *rsa.PublicKey, plainbytes []byte) ([]byte, bool) {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, key, plainbytes, nil)
	return ciphertext, err == nil
}

func RSAEncryptToB64(key *rsa.PublicKey, plainbytes []byte) (string, bool) {
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, key, plainbytes, nil)
	return base64.RawStdEncoding.EncodeToString(ciphertext), err == nil
}

func RSADecrypt(key *rsa.PrivateKey, ciphertext []byte) ([]byte, bool) {
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, key, ciphertext, nil)
	return plaintext, err == nil
}

func RSADecryptFromB64(key *rsa.PrivateKey, ciphertextb64 string) ([]byte, bool) {
	hash := sha256.New()
	cipherbytes, err := base64.RawStdEncoding.DecodeString(ciphertextb64)
	if err != nil {
		return nil, false
	}
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, key, cipherbytes, nil)
	return plaintext, err == nil
}

func RSADecryptFromB64ToStr(key *rsa.PrivateKey, ciphertextb64 string) (string, bool) {
	hash := sha256.New()
	cipherbytes, err := base64.RawStdEncoding.DecodeString(ciphertextb64)
	if err != nil {
		return "", false
	}
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, key, cipherbytes, nil)
	return string(plaintext), err == nil
}

func RSASign(key *rsa.PrivateKey, msg []byte) ([]byte, bool) {
	hash := sha256.New()
	hash.Write(msg)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash.Sum(nil)[:])
	return signature, err == nil
}

func RSASignToB64(key *rsa.PrivateKey, msg []byte) (string, bool) {
	hash := sha256.New()
	hash.Write(msg)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash.Sum(nil)[:])
	return base64.RawStdEncoding.EncodeToString(signature), err == nil
}

func RSAVerify(key *rsa.PublicKey, msg []byte, signature []byte) bool {
	hash := sha256.New()
	hash.Write(msg)
	err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash.Sum(nil)[:], signature)
	return err == nil
}

func RSAVerifyFromB64(key *rsa.PublicKey, msg []byte, signature string) bool {
	hash := sha256.New()
	hash.Write(msg)
	signaturebytes, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		return nil, false
	}
	err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash.Sum(nil)[:], signaturebytes)
	return err == nil
}
