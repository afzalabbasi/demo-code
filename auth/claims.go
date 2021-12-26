package auth

import (
	"os"
	"time"

	"github.com/afzalabbasi/demo-code/model"
	"github.com/golang-jwt/jwt"
)

// jwt token claims which contains info regarding user
type JwtUserClaim struct {
	ID        int    `json:"_id" db:"_id"`
	FirstName string `json:"firstName" db:"firstName"`
	LastName  string `json:"lastName" db:"lastName"`
	Email     string `json:"email" db:"email"`
	Role      int    `json:"role" db:"urole"`
	jwt.StandardClaims
}

func Token(user model.User) (string, error) {
	tNow := time.Now()
	tUTC := tNow
	newTUTC := tUTC.Add(time.Minute * 60)
	// Set custom claims
	claims := &JwtUserClaim{
		user.ID,
		user.FirstName,
		user.LastName,
		user.Email,
		user.Urole,
		jwt.StandardClaims{
			ExpiresAt: newTUTC.Unix(),
		},
	}
	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte(os.Getenv("JwtSecret")))
	if err != nil {
		return "", err
	}
	return t, nil
}
