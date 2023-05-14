package sshrsa

type SshKey struct {
	BitSize int `json:"bit_size" binding:"required,gte=515"`
}
