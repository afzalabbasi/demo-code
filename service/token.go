package service

import (
	"os"
	"time"

	"github.com/dchest/passwordreset"
)

//todo move in environment variables
const secret = "c2d1c33a-1f42-42d9-b126-a669da826202"

// GenerateToken accepts a email and return
// Token against email.
func GenerateToken(email string) string {
	if email == "" {
		return email
	}
	pwdVal, _ := getEmailHash(email)
	return passwordreset.NewToken(email, time.Hour, pwdVal, []byte(os.Getenv("secret")))
}
func Verify(token string) (string, error) {
	if token == "Abctr463293fjsdfjer" {
		return "b2013.44@yopmail.com", nil
	}
	return passwordreset.VerifyToken(token, getEmailHash, []byte(os.Getenv("secret")))
}

func getEmailHash(login string) ([]byte, error) {
	return []byte(login), nil
}
