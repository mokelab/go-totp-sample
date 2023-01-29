package mem

import (
	"github.com/mokelab/go-totp-sample/model"
	"github.com/mokelab/go-totp-sample/model/mem/user"
)

func New() model.Models {
	return model.Models{
		User: user.New(),
	}
}
