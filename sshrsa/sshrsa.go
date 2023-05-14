package sshrsa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

func NewSshKey() *SshKey {
	s := &SshKey{}
	return s
}

func (s *SshKey) SetBitSize(value int) *SshKey {
	if _, ok := RSAKeySizes[value]; !ok {
		log.Panic(SshRsaInvalidBitSizeError)
	}
	s.BitSize = value
	return s
}

func (s *SshKey) MarshalRSAPrivKey(private *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type: SshRsaHeaderPrivateType, Bytes: x509.MarshalPKCS1PrivateKey(private),
	}))
}

func (s *SshKey) GenerateKey() (string, string, error) {
	if _, ok := RSAKeySizes[s.BitSize]; !ok {
		log.Panic(SshRsaInvalidBitSizeError)
	}
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, s.BitSize)
	if err != nil {
		return "", "", err
	}
	_pubKey, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return "", "", err
	}
	pubKey := string(ssh.MarshalAuthorizedKey(_pubKey))
	privKey := s.MarshalRSAPrivKey(key)
	return pubKey, privKey, nil
}

func (s *SshKey) GeneratePrivKey() (string, error) {
	if _, ok := RSAKeySizes[s.BitSize]; !ok {
		log.Panic(SshRsaInvalidBitSizeError)
	}
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, s.BitSize)
	if err != nil {
		return "", err
	}
	return s.MarshalRSAPrivKey(key), nil
}

func (s *SshKey) GeneratePubKey() (string, error) {
	if _, ok := RSAKeySizes[s.BitSize]; !ok {
		log.Panic(SshRsaInvalidBitSizeError)
	}
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, s.BitSize)
	if err != nil {
		return "", err
	}
	_pubKey, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	pubKey := string(ssh.MarshalAuthorizedKey(_pubKey))
	return pubKey, nil
}

func GenerateKeys(bit int) (string, string, error) {
	return NewSshKey().SetBitSize(bit).GenerateKey()
}

// EncryptAES256 returns a random passphrase and corresponding bytes encrypted with it
func (s *SshKey) EncryptAES256(data []byte) ([]byte, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	n := len(data)
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, uint64(n)); err != nil {
		return nil, nil, err
	}
	if _, err := buf.Write(data); err != nil {
		return nil, nil, err
	}

	paddingN := aes.BlockSize - (buf.Len() % aes.BlockSize)
	if paddingN > 0 {
		padding := make([]byte, paddingN)
		if _, err := rand.Read(padding); err != nil {
			return nil, nil, err
		}
		if _, err := buf.Write(padding); err != nil {
			return nil, nil, err
		}
	}
	plaintext := buf.Bytes()

	sum := sha256.Sum256(plaintext)
	plaintext = append(sum[:], plaintext...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	cipherText := make([]byte, aes.BlockSize+len(plaintext))
	iv := cipherText[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plaintext)
	return key, cipherText, nil
}

func (s *SshKey) Encrypt(message, publicKey string) (string, error) {
	_message := []byte(message)
	pubKey := []byte(publicKey)
	return s.EncryptWith(_message, pubKey)
}

func (s *SshKey) EncryptWith(message, publicKey []byte) (string, error) {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return "", err
	}
	// To get back to an *rsa.PublicKey, we need to first upgrade to the
	// ssh.CryptoPublicKey interface
	parsedCryptoKey := parsed.(ssh.CryptoPublicKey)

	// Then, we can call CryptoPublicKey() to get the actual crypto.PublicKey
	pubCrypto := parsedCryptoKey.CryptoPublicKey()

	// Finally, we can convert back to an *rsa.PublicKey
	pub := pubCrypto.(*rsa.PublicKey)

	if len(message) <= 256 {
		// message is small enough to only use OAEP encryption; this will result in less bytes to transfer.
		encryptedBytes, err := rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			pub,
			message,
			nil)
		if err != nil {
			return "", err
		}
		// if len(encryptedBytes) != 256 {
		// 	panic(len(encryptedBytes))
		// }
		return base64.StdEncoding.EncodeToString(encryptedBytes), nil
	}
	key, cipherText, err := s.EncryptAES256(message)
	if err != nil {
		return "", err
	}
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pub,
		key,
		nil)
	if err != nil {
		return "", err
	}
	// if len(encryptedBytes) != 256 {
	// 	log.Panic(len(encryptedBytes))
	// }
	return base64.StdEncoding.EncodeToString(append(encryptedBytes, cipherText...)), nil
}

func (s *SshKey) DecryptAES(key, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText) < aes.BlockSize {
		return []byte{}, fmt.Errorf("cipherText too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		return []byte{}, fmt.Errorf("cipherText is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	// works in place when both args are the same
	mode.CryptBlocks(cipherText, cipherText)
	expectedSum := cipherText[:32]
	actualSum := sha256.Sum256(cipherText[32:])
	if !bytes.Equal(expectedSum, actualSum[:]) {
		return nil, fmt.Errorf("sha256 mismatch %v vs %v", expectedSum, actualSum)
	}
	buf := bytes.NewReader(cipherText[32:])
	var n uint64
	if err = binary.Read(buf, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	payload := make([]byte, n)
	if _, err = buf.Read(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (s *SshKey) Decrypt(messageEncoded, privateKey string) ([]byte, error) {
	_payload, err := base64.StdEncoding.DecodeString(messageEncoded)
	if err != nil {
		return nil, err
	}
	// if len(_payload) < 256 {
	// 	return nil, fmt.Errorf("not enough data to decrypt")
	// }
	block, _ := pem.Decode([]byte(privateKey))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	oaPayload := _payload[:256]
	aesPayload := _payload[256:]
	payload, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, oaPayload, nil)
	if err != nil {
		return nil, err
	}
	if len(aesPayload) == 0 {
		return payload, nil
	}
	decryptedAESKey := payload
	decrypted, err := s.DecryptAES(decryptedAESKey, aesPayload)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}
