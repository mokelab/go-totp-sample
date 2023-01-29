package entity

type User struct {
	Username        string
	TotpSecret      string
	SecretVerified  bool
	SetupTotpSecret string
}

func (u *User) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"username":      u.Username,
		"totp_verified": u.SecretVerified,
	}
}
