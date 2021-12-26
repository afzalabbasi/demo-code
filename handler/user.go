package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/afzalabbasi/demo-code/auth"
	"github.com/afzalabbasi/demo-code/service"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/afzalabbasi/demo-code/common"
	"github.com/afzalabbasi/demo-code/model"
	"github.com/afzalabbasi/demo-code/network/response"
	"github.com/afzalabbasi/demo-code/system/messages"
	"github.com/labstack/echo/v4"
)

type TokenInformation struct {
	Data       string
	Message    string
	SubMessage string
}

// UpdateUser Profile godoc
// @Summary Update User Profile
// @Accept json
// @Produce json
// @Param update user body model.User true "Update User Profile Data"
// @Param id path string true "User ID"
// @Success 200 {object} model.SuccessResponse
// @Failure 400 {object} model.BadResponse
// @Router /user/:id [put]
// @Description
// UpdateUser method accepts a user id from user
// In the form of Parameters. stub user information to be populated from the body
// Validate the json request and user  information
// In database against user id
func UpdateUser(app *common.App) func(c echo.Context) error {
	return func(c echo.Context) error {
		userId := c.Param("id")
		uid, _ := strconv.Atoi(userId)
		// Stub an user information to be populated from the body
		u := model.User{}
		// convert json to struct
		if err := c.Bind(&u); err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		// validate input request body
		if err := c.Validate(u); err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		u.Email = strings.ToLower(u.Email)
		//check user is exit or not against user id
		user, err1 := app.DB.GetUserById(uid)
		if err1 != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusNotFound, m)
		}
		//encrypt password
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.MinCost)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		user.FirstName = u.FirstName
		user.LastName = u.LastName
		user.Password = string(hash)
		user.Email = u.Email
		user.UpdateDate = time.Now()
		//update user information in user table
		userinfo, err := app.DB.UpdateUser(*user)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		m := model.SuccessResponse{Data: userinfo, Message: "SuccessFully", SubMessage: "SuccessFully"}
		return c.JSON(http.StatusOK, m)

	}
}

// GetUser Profile godoc
// @Summary GetUser Profile
// In the form of Parameters
// Return user  information
// From database against user id
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} model.SuccessResponse
// @Failure 400 {object} model.BadResponse
// @Router /user/:id [get]
// @Description
// GetUser method accepts a user id from user
// In the form of Parameters
// Return user  information
// From database against user id
func GetUser(app *common.App) func(c echo.Context) error {
	return func(c echo.Context) error {
		userId := c.Param("id")
		uid, _ := strconv.Atoi(userId)
		// Stub an user information to be populated from the body

		//check user is exit or not against user id
		user, err1 := app.DB.GetUserById(uid)
		if err1 != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusNotFound, m)
		}
		m := model.SuccessResponse{Data: user, Message: "SuccessFully", SubMessage: "SuccessFully"}
		return c.JSON(http.StatusOK, m)

	}
}

// ListUser Profile godoc
// @Summary List All User
// From database
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} model.SuccessResponse
// @Failure 400 {object} model.BadResponse
// @Router /user [get]
// @Description
// ListUser return user's  information
// From database
func ListUser(app *common.App) func(c echo.Context) error {
	return func(c echo.Context) error {
		//check user is exit or not against user id
		user, err1 := app.DB.GetUser()
		if err1 != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusNotFound, m)
		}
		m := model.SuccessResponse{Data: user, Message: "SuccessFully", SubMessage: "SuccessFully"}
		return c.JSON(http.StatusOK, m)

	}
}

// AssignRoleToUser godoc
// @Summary AssignRoleToUser
// @Param id path string true "User ID"
// @Param notification body model.RoleInformation true "RoleInformation Data"
// @Accept json
// @Produce json
// @Success 200 {object} model.SuccessResponse
// @Failure 400 {object} model.BadResponse
// @Router /assignrole/:uid [put]
// @Description
// AssignRoleToUser method accepts a user id from user
// In the form of Parameters. stub role information to be populated from the body
// Validate the json request and assign role to user and update user information
// In database against user id
func AssignRoleToUser(app *common.App) func(c echo.Context) error {
	return func(c echo.Context) error {
		userId := c.Param("uid")
		uid, _ := strconv.Atoi(userId)
		u := model.RoleInformation{}
		// convert json to struct
		if err := c.Bind(&u); err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		// validate input request body
		if err := c.Validate(u); err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		//check user is exit or not against user id
		user, err1 := app.DB.GetUserById(uid)
		if err1 != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusNotFound, m)
		}
		user.Urole = u.RoleId
		user.UpdateDate = time.Now()
		//update user information in user table
		userinfo, err := app.DB.UpdateUser(*user)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		m := model.SuccessResponse{Data: userinfo, Message: "SuccessFully", SubMessage: "SuccessFully"}
		return c.JSON(http.StatusOK, m)

	}
}

// SignUp godoc
// @Summary Create a User
// @Accept json
// @Produce json
// @Param signup body model.User true "New User Data"
// @Success 201 {object} model.SuccessResponse
// @Failure 400 {object} model.BadResponse
// @Router /signup [post]
// @Description
// SignUp method stub user information to be populated from the body
// Validate the json request. check user email already exist or not
// Save user information in database.
func SignUp(app *common.App) func(c echo.Context) error {
	return func(c echo.Context) error {
		// Stub an user information to be populated from the body
		u := model.User{}
		// convert json to struct
		if err := c.Bind(&u); err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		// validate input request body
		if err := c.Validate(u); err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		u.Email = strings.ToLower(u.Email)
		//get user from database against email
		user, err1 := app.DB.GetUserByEmail(u.Email)
		if err1 == nil && user != nil {
			m := model.SuccessResponse{Data: user, Message: "User is already present with this email", SubMessage: "Please check  email...You have received verification email"}
			return c.JSON(http.StatusAccepted, m)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.MinCost)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		u.Password = string(hash)
		u.CreateDate = time.Now()
		u.UpdateDate = time.Now()
		if u.ParentEmail != "" {
			u.HaveConcent = false
		} else {
			u.HaveConcent = true
		}
		u.IsVerified = false
		if err := app.DB.Save(u); err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		//send email to user for verification
		err = sendVerifyEmail(&u)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		return response.CreateSuccessResponseWithoutData(&c, http.StatusCreated, "Please verify you account", "Account verification email has been send to you email address")

	}
}

// Verify godoc
// @Summary Verify User
// @Produce json
// @QueryParam id path string true "User ID"
// @Success 200 {object} model.SuccessResponse
// @Failure 400 {object} model.BadResponse
// @Router /confirm [get]
// @Description
// Verify method accepts a token in the from of query parameters
// Get email against token and verify user account.
func Verify(app *common.App) func(c echo.Context) error {
	return func(c echo.Context) error {
		t := c.QueryParam("token")
		if t == "" {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: "Invalid token"}
			return c.JSON(http.StatusBadRequest, m)
		}
		email, err := service.Verify(t)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: "Invalid token"}
			return c.JSON(http.StatusBadRequest, m)
		}
		//get user from database against email
		user, err := app.DB.GetUserByEmail(email)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusNotFound, m)
		}
		user.IsVerified = true
		err = app.DB.VerifyUser(*user)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: err.Error()}
			return c.JSON(http.StatusBadRequest, m)
		}
		if user.HaveConcent {
			err := sendVerifyDoneEmail(user)
			if err != nil {
				m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
				return c.JSON(http.StatusBadRequest, m)
			}
			err = AssignJwtToken(c, *user)
			if err != nil {
				m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
				return c.JSON(http.StatusBadRequest, m)
			}
			user.Password = ""
			m := model.SuccessResponse{Data: user, Message: "User Created SuccessFully", SubMessage: "User Created SuccessFully"}
			return c.JSON(http.StatusOK, m)
		} else {
			m := model.SuccessResponse{Data: user, Message: "User Created SuccessFully", SubMessage: "Parent Must Verified Your Activity...."}
			return c.JSON(http.StatusOK, m)
		}
	}
}

// ForgotPassword godoc
// @Summary ForgotPassword Email
// @Produce json
// @QueryParam email path string true "User Email"
// @Success 200 {object} model.SuccessResponse
// @Failure 400 {object} model.BadResponse
// @Router /sendforgot [get]
// @Description
// ForgotPassword method accepts a email from user in the
// From of query parameters and send forgot password email
// To user.
func ForgotPassword(app *common.App) func(c echo.Context) error {
	return func(c echo.Context) error {
		email := c.QueryParam("email")

		if email == "" {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: "email is compulsory"}
			return c.JSON(http.StatusBadRequest, m)
		}
		//get user from database against email
		user, err := app.DB.GetUserByEmail(email)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: err.Error()}
			return c.JSON(http.StatusBadRequest, m)
		}
		if !user.IsVerified {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: "you are not authorized to perform this action"}
			return c.JSON(http.StatusBadRequest, m)
		}
		err = forgotpasswordEmail(user)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		return response.CreateSuccessResponseWithoutData(&c, http.StatusOK, "Success", "In few minutes you will receive email with link to use to recover your password")

	}
}

// ResetPassword godoc
// @Summary ResetPassword
// @Produce json
// @QueryParam email path string true "User Email"
// @QueryParam token path string true "Token"
// @Success 200 {object} model.SuccessResponse
// @Failure 400 {object} model.BadResponse
// @Router /resetpassword [get]
// @Description
// ResetPassword method accept a token and new password from user
// In the form of query parameters and reset user password.
func ResetPassword(app *common.App) func(c echo.Context) error {
	return func(c echo.Context) error {
		t := c.QueryParam("token")
		newPassword := c.QueryParam("newPassword")
		if t == "" || newPassword == "" {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: "Invalid input"}
			return c.JSON(http.StatusBadRequest, m)
		}
		email, err := service.Verify(t)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: "Invalid token"}
			return c.JSON(http.StatusBadRequest, m)
		}
		//get user from database against email
		user, err := app.DB.GetUserByEmail(email)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: err.Error()}
			return c.JSON(http.StatusBadRequest, m)
		}
		if !user.IsVerified {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: "you are not authorized to perform this action"}
			return c.JSON(http.StatusBadRequest, m)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.MinCost)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		user.Password = string(hash)
		err = app.DB.ResetPassword(*user, user.Password)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		user.Password = ""
		uj, _ := json.Marshal(user)
		// generate jwt token
		err = AssignJwtToken(c, *user)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		m := model.SuccessResponse{Data: uj, Message: "Success", SubMessage: "Success"}
		return c.JSON(http.StatusAccepted, m)
	}
}

// Login godoc
// @Summary Login
// @Accept json
// @Produce json
// @Param signup body model.Login true "Login Information"
// @Success 200 {object} model.SuccessResponse
// @Failure 400 {object} model.BadResponse
// @Router /login [post]
// @Description
// Login method stub login information to be populated from the body
// Validate the json request, set jwt token in header and returns user information.
func Login(app *common.App) func(c echo.Context) error {
	return func(c echo.Context) error {
		u := model.Login{}
		// convert json to struct
		if err := c.Bind(&u); err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		// validate input request body
		if err := c.Validate(u); err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		u.Email = strings.ToLower(u.Email)
		//get user from database against email
		user, err1 := app.DB.GetUserByEmail(u.Email)
		if err1 != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: err1.Error()}
			return c.JSON(http.StatusBadRequest, m)
		}
		fmt.Println(user.Password, u.Password)
		fmt.Println([]byte(user.Password), []byte(u.Password))
		err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(u.Password))
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: err.Error()}
			return c.JSON(http.StatusBadRequest, m)
		}
		if !user.IsVerified && !user.HaveConcent {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: "you are not authorized to perform this action"}
			return c.JSON(http.StatusBadRequest, m)
		}
		// generate jwt token
		err = AssignJwtToken(c, *user)
		if err != nil {
			m := model.BadResponse{Message: messages.PleaseTryAgain, SubMessage: messages.OperationFailed}
			return c.JSON(http.StatusBadRequest, m)
		}
		user.Password = ""
		m := model.SuccessResponse{Data: user, Message: "SuccessFully", SubMessage: "SuccessFully"}
		return c.JSON(http.StatusOK, m)
	}
}

func forgotpasswordEmail(user *model.User) error {

	// extract web page url
	homeurl := "localhost:8080"
	if !strings.HasPrefix(homeurl, "http") {
		homeurl = "http://" + homeurl
	}

	if !strings.HasSuffix(homeurl, "/") {
		homeurl = homeurl + "/account/"
	}

	token := service.GenerateToken(user.Email)

	var subject string

	subject = "Reset Password"
	homeurl = homeurl + "auth/reset" + "?token=" + token
	subject = "Reset Password"
	host, err := host(homeurl)
	if err != nil || host == "" {
		return err
	}
	host = strings.TrimPrefix(host, "www.")
	fmt.Println(homeurl)
	go func() {
		absPath, _ := filepath.Abs("templates/forgot-password-template.gohtml")
		fmt.Println(absPath)
		t, err := template.ParseFiles(absPath)
		if err != nil {
			fmt.Println("Error : ", err.Error())
			return
		}
		data := struct {
			ActionUrl string
		}{
			ActionUrl: homeurl,
		}

		var tpl bytes.Buffer
		err = t.Execute(&tpl, data)
		if err != nil {
			fmt.Println("Error : ", err.Error())
			return
		}
		result := tpl.String()

		service.SendEmail(service.EmailOptions{
			FromEmail:   "no-reply@" + host,
			Subject:     subject,
			ToName:      user.FirstName,
			ToEmail:     user.Email,
			TextContent: subject,
			HtmlContent: result,
		})
	}()

	return nil
}

func sendVerifyDoneEmail(user *model.User) error {
	// extract web page url
	go func() {
		absPath, _ := filepath.Abs("templates/verification-doneemail-template.gohtml")
		t, err := template.ParseFiles(absPath)
		if err != nil {
			return
		}
		var tpl bytes.Buffer
		err = t.Execute(&tpl, nil)
		if err != nil {
			return
		}
		result := tpl.String()
		service.SendEmail(service.EmailOptions{
			FromEmail:   "no-reply@" + "sourcemedicine.com",
			Subject:     "Account Verification Email",
			ToName:      user.FirstName,
			ToEmail:     user.Email,
			TextContent: "Account Verification Email",
			HtmlContent: result,
		})

	}()
	return nil

}
func sendVerifyEmail(user *model.User) error {
	// extract web page url
	homeUrl := "localhost:8080"
	if !strings.HasPrefix(homeUrl, "http") {
		homeUrl = "http://" + homeUrl
	}
	if !strings.HasSuffix(homeUrl, "/") {
		homeUrl = homeUrl + "/"
	}
	token := service.GenerateToken(user.Email)
	var subject string
	var endPoint string
	endPoint = "confirm"
	subject = "Confirm Account"
	homeUrl = homeUrl + endPoint + "?token=" + token
	hostnew, err := host(homeUrl)
	if err != nil || hostnew == "" {
		return err
	}
	hostnew = strings.TrimPrefix(hostnew, "www.")
	go func() {
		var absPath string

		if user.ParentEmail != "" && user.Age <= 13 {
			endPoint = "haveconcent"
			subject = "Confirm Account by Parent"
			urlnew := "localhost:8080"
			if !strings.HasPrefix(urlnew, "http") {
				urlnew = "http://" + urlnew
			}
			if !strings.HasSuffix(urlnew, "/") {
				urlnew = urlnew + "/"
			}
			url1 := urlnew + endPoint + "?token=" + token
			host1, err1 := host(url1)
			if err1 != nil || host1 == "" {
				return
			}
			host1 = strings.TrimPrefix(host1, "www.")
			absPath, _ = filepath.Abs("templates/verify-parentemail-template.gohtml")
			t, err := template.ParseFiles(absPath)
			if err != nil {
				return
			}
			data := struct {
				ActionUrl string
			}{
				ActionUrl: homeUrl,
			}

			var tpl bytes.Buffer
			err = t.Execute(&tpl, data)
			if err != nil {
				return
			}
			result := tpl.String()

			service.SendEmail(service.EmailOptions{
				FromEmail:   "no-reply@" + host1,
				Subject:     subject,
				ToName:      user.FirstName,
				ToEmail:     user.ParentEmail,
				TextContent: subject,
				HtmlContent: result,
			})
			absPath, _ = filepath.Abs("templates/verify-email-template.gohtml")
			t, err = template.ParseFiles(absPath)
			if err != nil {
				return
			}
			data = struct {
				ActionUrl string
			}{
				ActionUrl: homeUrl,
			}

			var tpl1 bytes.Buffer
			err = t.Execute(&tpl1, data)
			if err != nil {
				return
			}
			result = tpl1.String()

			service.SendEmail(service.EmailOptions{
				FromEmail:   "no-reply@" + hostnew,
				Subject:     subject,
				ToName:      user.FirstName,
				ToEmail:     user.Email,
				TextContent: subject,
				HtmlContent: result,
			})

		} else {
			absPath, _ = filepath.Abs("templates/verify-email-template.gohtml")
			t, err := template.ParseFiles(absPath)
			if err != nil {
				return
			}
			data := struct {
				ActionUrl string
			}{
				ActionUrl: homeUrl,
			}

			var tpl bytes.Buffer
			err = t.Execute(&tpl, data)
			if err != nil {
				return
			}
			result := tpl.String()

			service.SendEmail(service.EmailOptions{
				FromEmail:   "no-reply@" + hostnew,
				Subject:     subject,
				ToName:      user.FirstName,
				ToEmail:     user.Email,
				TextContent: subject,
				HtmlContent: result,
			})
		}

	}()

	return nil
}
func host(source string) (string, error) {
	u, err := url.Parse(source)
	if err != nil {
		return "", err
	}
	return u.Host, nil
}

// helper
func AssignJwtToken(c echo.Context, user model.User) error {

	token, err := auth.Token(user)
	if err != nil {
		logrus.Debugln("AssignJwtToken ::: token not generated for user ")
		logrus.Debugln(user)
		return err
	}
	c.Response().Header().Set("x_auth_token", token)

	return nil
}
