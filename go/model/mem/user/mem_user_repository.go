package user

import (
	"crypto/rand"
	"errors"
	"fmt"
	"image"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/mokelab/go-totp-sample/entity"
	"github.com/mokelab/go-totp-sample/model"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	secretKey = "XhjA+5B11wfvm24dVSPsh8MebKG2uEVOhJ23OMw7/LtqMURL+geISw=="
)

type repo struct {
	users map[string]entity.User
}

func New() model.UserRepository {
	return &repo{
		users: make(map[string]entity.User),
	}
}

// Create implements model.UserRepository
func (r *repo) Create(username string) (entity.User, error) {
	_, ok := r.users[username]
	if ok {
		return entity.User{}, errors.New("already exists")
	}
	u := entity.User{
		Username:       username,
		TotpSecret:     "",
		SecretVerified: false,
	}
	r.users[username] = u
	return u, nil
}

// GetByUsername implements model.UserRepository
func (r *repo) GetByUsername(username string) (entity.User, error) {
	u, ok := r.users[username]
	if !ok {
		return entity.User{}, errors.New("not found")
	}
	return u, nil
}

// Login implements model.UserRepository
func (r *repo) Login(username string) (string, error) {
	u, ok := r.users[username]
	if !ok {
		return "", errors.New("not found")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":     username,
		"totp_enabled": u.SecretVerified,
		"exp":          time.Now().Add(1 * time.Hour).Unix(),
	})
	return token.SignedString([]byte(secretKey))
}

// GetSession implements model.UserRepository
func (*repo) GetSession(jwtStr string) (entity.Session, error) {
	token, err := jwt.Parse(jwtStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return entity.Session{}, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return entity.Session{
			Username:    claims["username"].(string),
			TotpEnabled: claims["totp_enabled"].(bool),
		}, nil
	} else {
		return entity.Session{}, errors.New("Failed to parse token")
	}
}

// CreateTotpCode implements model.UserRepository
func (r *repo) CreateTotpCode(username string) (image.Image, error) {
	u, err := r.GetByUsername(username)
	if err != nil {
		return nil, err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "example.mokelab.com",
		AccountName: username,
		Period:      30,
		SecretSize:  20,
		Secret:      []byte{},
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		Rand:        rand.Reader,
	})
	if err != nil {
		return nil, err
	}
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, err
	}
	u.SetupTotpSecret = key.Secret()
	r.users[username] = u
	return img, nil
}

// VerifySetupTotpCode implements model.UserRepository
func (r *repo) VerifySetupTotpCode(username string, passCode string) (bool, error) {
	u, err := r.GetByUsername(username)
	if err != nil {
		return false, err
	}
	if len(u.SetupTotpSecret) == 0 {
		return false, errors.New("not prepared")
	}
	valid := totp.Validate(passCode, u.SetupTotpSecret)
	if valid {
		u.TotpSecret = u.SetupTotpSecret
		u.SetupTotpSecret = ""
		return true, nil
	} else {
		return false, nil
	}
}
