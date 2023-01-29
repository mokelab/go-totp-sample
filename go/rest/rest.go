package rest

import (
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/mokelab/go-totp-sample/model"
)

func InitRouter(m *mux.Router, models *model.Models) {
	m.HandleFunc("/api/signup", signup(models)).Methods("POST")
	m.HandleFunc("/api/login", login(models)).Methods("POST")
	m.HandleFunc("/api/totp/setup", totpSetup(models)).Methods("POST")
	m.HandleFunc("/api/totp/setup/verify", totpSetupVerify(models)).Methods("POST")
}

func signup(models *model.Models) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		var data map[string]interface{}
		err = json.Unmarshal(bodyBytes, &data)
		if err != nil {
			writeError(w, http.StatusBadRequest, "request body is not JSON")
			return
		}
		username, _ := data["username"].(string)
		if len(username) == 0 {
			writeError(w, http.StatusBadRequest, "username must not be empty")
			return
		}
		u, err := models.User.Create(username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeMap(w, u.ToMap())
	}
}

func login(models *model.Models) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		var data map[string]interface{}
		err = json.Unmarshal(bodyBytes, &data)
		if err != nil {
			writeError(w, http.StatusBadRequest, "request body is not JSON")
			return
		}
		username, _ := data["username"].(string)
		if len(username) == 0 {
			writeError(w, http.StatusBadRequest, "username must not be empty")
			return
		}
		token, err := models.User.Login(username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeMap(w, map[string]interface{}{
			"token": token,
		})
	}
}

func totpSetup(models *model.Models) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		authValues := strings.SplitN(authorization, " ", 2)
		jwtToken := authValues[1]

		session, err := models.User.GetSession(jwtToken)
		if err != nil {
			fmt.Printf("getsession error %s\n", err)
			writeError(w, http.StatusBadRequest, "wrong token")
			return
		}
		username := session.Username
		img, err := models.User.CreateTotpCode(username)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		err = png.Encode(w, img)
		if err != nil {
			fmt.Printf("Failed to encode %s", err)
			return
		}
	}
}

func totpSetupVerify(models *model.Models) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		authValues := strings.SplitN(authorization, " ", 2)
		jwtToken := authValues[1]

		session, err := models.User.GetSession(jwtToken)
		if err != nil {
			fmt.Printf("getsession error %s\n", err)
			writeError(w, http.StatusBadRequest, "wrong token")
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		var data map[string]interface{}
		err = json.Unmarshal(bodyBytes, &data)
		if err != nil {
			writeError(w, http.StatusBadRequest, "request body is not JSON")
			return
		}

		username := session.Username
		code, _ := data["code"].(string)
		valid, err := models.User.VerifySetupTotpCode(username, code)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if valid {
			writeMap(w, map[string]interface{}{
				"result": "verified",
			})
		} else {
			writeMap(w, map[string]interface{}{
				"result": "failed",
			})
		}
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	writeMap(w, map[string]interface{}{
		"msg": msg,
	})
}

func writeMap(w http.ResponseWriter, m map[string]interface{}) {
	data, err := json.Marshal(m)
	if err != nil {
		fmt.Printf("Failed to marshal %s\n", err)
		return
	}
	w.Write(data)
}
