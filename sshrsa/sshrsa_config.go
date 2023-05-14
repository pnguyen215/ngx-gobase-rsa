package sshrsa

import "fmt"

const (
	SshRsaPublicPrefix             = "ssh-rsa"
	SshRsaHeaderPrivateType        = "RSA PRIVATE KEY"
	SshRsaHeaderPrivateOpenSshType = "OPENSSH PRIVATE KEY"
)

const (
	RSA515KeySize  = 515
	RSA1024KeySize = 1024
	RSA2048KeySize = 2048
	RSA3072KeySize = 3072
	RSA4096KeySize = 4096
)

var (
	RSAKeySizes map[int]bool = map[int]bool{
		RSA515KeySize:  true,
		RSA1024KeySize: true,
		RSA2048KeySize: true,
		RSA3072KeySize: true,
		RSA4096KeySize: true,
	}
)

var (
	SshRsaInvalidBitSizeError = fmt.Sprintf("Invalid bit_size, refer value from %s", "sshrsa.RSAKeySizes")
)
