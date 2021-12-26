package auth

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

type AppContext struct {
	echo.Context
	ID     int    `json:"_id" db:"_id"`
	Email  string `json:"email" db:"email"`
	RoleId int    `json:"role_id" db:"urole"`
}

func MiddlewareRes(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		tNow := time.Now()
		tUTC := tNow
		newTUTC := tUTC.Add(time.Hour)
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(*JwtUserClaim)
		claims.ExpiresAt = newTUTC.Unix()
		// Generate encoded token and send it as response.
		t, err := user.SignedString([]byte(os.Getenv("JwtSecret")))
		if err != nil {
			return err
		}
		c.Response().Header().Set("x_auth_token", t)
		appContext := AppContext{Context: c, ID: claims.ID, Email: claims.Email, RoleId: claims.Role}
		if err := next(appContext); err != nil {
			c.Error(err)
		}
		return nil
	}
}
