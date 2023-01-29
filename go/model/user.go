package model

import (
	"image"

	"github.com/mokelab/go-totp-sample/entity"
)

type UserRepository interface {
	Create(username string) (entity.User, error)
	GetByUsername(username string) (entity.User, error)

	Login(username string) (string, error)
	GetSession(jwtStr string) (entity.Session, error)

	CreateTotpCode(username string) (image.Image, error)
	VerifySetupTotpCode(username, passCode string) (bool, error)
}
