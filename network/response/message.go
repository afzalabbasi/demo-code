package response

import (
	"fmt"
	"github.com/labstack/echo/v4"
)

func CreateSuccessResponseWithoutData(c *echo.Context, requestCode int, message string, subMessage string) error {

	localC := *c
	response := fmt.Sprintf("{\"data\":{},\"message\":%q,\"submessage\":%q}", message, subMessage)
	return localC.JSONBlob(requestCode, []byte(response))
}
