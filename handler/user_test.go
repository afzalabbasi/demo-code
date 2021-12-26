package handler

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/afzalabbasi/demo-code/auth"
	"github.com/afzalabbasi/demo-code/common"
	"github.com/afzalabbasi/demo-code/model"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
)

type AnyTime struct {
}

func TestLogin(t *testing.T) {
	app, mock, err := common.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.DB.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("123456789"), bcrypt.MinCost)
	testLogin := model.Login{
		Email:    "test@yopmail.com",
		Password: "123456789",
	}
	mock.ExpectQuery(`SELECT \* FROM user`).WithArgs(
		testLogin.Email,
	).WillReturnRows(sqlmock.NewRows([]string{"_id", "firstname", "lastname", "email", "password", "urole",
		"isverified", "isadvisor", "onleave", "parentemail", "age", "haveconcent", "create_date", "update_date"}).AddRow(1, "test", "test", "test@yopmail.com", hash, 1,
		true, false, false, "", 30, false, time.Now(), time.Now()))

	jsonLogin, _ := json.Marshal(testLogin)
	requestReader := bytes.NewReader(jsonLogin)
	req := httptest.NewRequest(http.MethodGet, "/login", requestReader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := app.Echo.NewContext(req, rec)
	err = Login(app)(auth.AppContext{Context: ctx, ID: 1, RoleId: 2})
	// Assertions
	if assert.NoError(t, err) {
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestUpdateUser(t *testing.T) {
	app, mock, err := common.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.DB.Close()

	mock.ExpectQuery(`SELECT \* FROM user`).WithArgs(
		1,
	).WillReturnRows(sqlmock.NewRows([]string{"_id", "firstname", "lastname", "email", "advisorid", "password", "urole",
		"isverified", "isadvisor", "onleave", "parentemail", "age", "haveconcent", "create_date", "update_date"}).AddRow(1, "test", "test", "test@yopmail.com", 1, "fesfsefsef123456", 1,
		false, false, false, "test1@yopmail.com", 30, true, time.Now(), time.Now()))

	testUser := model.User{
		ID:          1,
		FirstName:   "test",
		LastName:    "test",
		Email:       "test@yopmail.com",
		Password:    "fesfsefsef123456",
		AdvisorId:   1,
		Urole:       1,
		IsVerified:  false,
		IsAdvisor:   false,
		OnLeave:     false,
		ParentEmail: "test1@yopmail.com",
		Age:         30,
		HaveConcent: true,
		CreateDate:  time.Now().UTC(),
		UpdateDate:  time.Now().UTC(),
	}
	query := `UPDATE users SET firstname = $2, lastname = $3, email = $4, advisorid = $5, urole = $6, isverified = $7, isadvisor = $8, onleave = $9, parentemail = $10, age = $11, haveconcent =$12 WHERE _id = $1;`
	mock.ExpectExec(regexp.QuoteMeta(query)).WithArgs(testUser.ID, testUser.FirstName, testUser.LastName, testUser.Email, testUser.AdvisorId, testUser.Urole, testUser.IsVerified, testUser.IsAdvisor, testUser.OnLeave, testUser.ParentEmail, testUser.Age, testUser.HaveConcent).WillReturnResult(sqlmock.NewResult(0, 1))
	jsonUser, _ := json.Marshal(testUser)
	requestReader := bytes.NewReader(jsonUser)
	req := httptest.NewRequest(http.MethodDelete, "/user:/id", requestReader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := app.Echo.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues("1")
	err = UpdateUser(app)(auth.AppContext{Context: ctx, ID: 1, RoleId: 2})
	// Assertions
	if assert.NoError(t, err) {
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestAssignRoleUser(t *testing.T) {
	app, mock, err := common.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.DB.Close()

	mock.ExpectQuery(`SELECT \* FROM user`).WithArgs(
		1,
	).WillReturnRows(sqlmock.NewRows([]string{"_id", "firstname", "lastname", "email", "advisorid", "password", "urole",
		"isverified", "isadvisor", "onleave", "parentemail", "age", "haveconcent", "create_date", "update_date"}).AddRow(1, "test", "test", "test@yopmail.com", 1, "fesfsefsef123456", 1,
		false, false, false, "test1@yopmail.com", 30, true, time.Now(), time.Now()))

	testUser := model.User{
		ID:          1,
		FirstName:   "test",
		LastName:    "test",
		Email:       "test@yopmail.com",
		Password:    "fesfsefsef123456",
		Urole:       1,
		AdvisorId:   1,
		ParentEmail: "test1@yopmail.com",
		Age:         30,
		HaveConcent: true,
		IsVerified:  false,
		IsAdvisor:   false,
		OnLeave:     false,
		CreateDate:  time.Now().UTC(),
		UpdateDate:  time.Now().UTC(),
	}
	roleTestInformation := model.RoleInformation{
		RoleId: 1,
	}
	query := `UPDATE users SET firstname = $2, lastname = $3, email = $4, advisorid = $5, urole = $6, isverified = $7, isadvisor = $8, onleave = $9, parentemail = $10, age = $11, haveconcent =$12 WHERE _id = $1;`
	mock.ExpectExec(regexp.QuoteMeta(query)).WithArgs(testUser.ID, testUser.FirstName, testUser.LastName, testUser.Email, testUser.AdvisorId, testUser.Urole, testUser.IsVerified, testUser.IsAdvisor, testUser.OnLeave, testUser.ParentEmail, testUser.Age, testUser.HaveConcent).WillReturnResult(sqlmock.NewResult(0, 1))
	jsonUser, _ := json.Marshal(roleTestInformation)
	requestReader := bytes.NewReader(jsonUser)
	req := httptest.NewRequest(http.MethodDelete, "/user:/id", requestReader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := app.Echo.NewContext(req, rec)
	ctx.SetParamNames("uid")
	ctx.SetParamValues("1")
	err = AssignRoleToUser(app)(auth.AppContext{ctx, 1, "", 2})
	// Assertions
	if assert.NoError(t, err) {
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestVerifyUser(t *testing.T) {
	app, mock, err := common.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.DB.Close()

	mock.ExpectQuery(`SELECT \* FROM user`).WithArgs(
		"b2013.44@yopmail.com",
	).WillReturnRows(sqlmock.NewRows([]string{"_id", "firstname", "lastname", "email", "advisorid", "password", "urole",
		"isverified", "isadvisor", "onleave", "parentemail", "age", "haveconcent", "create_date", "update_date"}).AddRow(1, "test", "test", "test@yopmail.com", 1, "fesfsefsef123456", 1,
		false, false, false, "b2013.44@yopmail.com", 30, true, time.Now(), time.Now()))

	testUser := model.User{
		ID:          1,
		FirstName:   "test",
		LastName:    "test",
		Email:       "test@yopmail.com",
		Password:    "fesfsefsef123456",
		Urole:       1,
		IsVerified:  true,
		IsAdvisor:   false,
		OnLeave:     false,
		ParentEmail: "test1@yopmail.com",
		Age:         30,
		HaveConcent: true,
		CreateDate:  time.Now().UTC(),
		UpdateDate:  time.Now().UTC(),
	}
	testresult := TokenInformation{
		Data:       "aBCDHTRiopJDKLFG",
		Message:    "SuccessFully",
		SubMessage: "SuccessFully",
	}
	b, _ := json.Marshal(testresult)
	data := TokenInformation{}
	err = json.Unmarshal(b, &data)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(data)

	query := `UPDATE users SET isverified = $2 WHERE _id = $1;`
	mock.ExpectExec(regexp.QuoteMeta(query)).WithArgs(testUser.ID, testUser.IsVerified).WillReturnResult(sqlmock.NewResult(0, 1))
	// create a listener with the desired port.
	l, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, testresult)
	}))

	// NewUnstartedServer creates a listener. Close that listener and replace
	// with the one we created.
	defer ts.Listener.Close()
	ts.Listener = l
	// Start the server.
	ts.Start()
	// Cleanup.
	defer ts.Close()
	jsonUser, _ := json.Marshal(testUser)
	requestReader := bytes.NewReader(jsonUser)
	req := httptest.NewRequest(http.MethodPost, "/user:/id", requestReader)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := app.Echo.NewContext(req, rec)
	// need to pass token here that we get in email
	ctx.QueryParams().Set("token", "Abctr463293fjsdfjer")
	err = Verify(app)(auth.AppContext{ctx, 1, "", 2})
	// Assertions
	if assert.NoError(t, err) {
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

func TestForgotPassword(t *testing.T) {
	app, mock, err := common.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.DB.Close()

	mock.ExpectQuery(`SELECT \* FROM user`).WithArgs(
		"test@yopmail.com",
	).WillReturnRows(sqlmock.NewRows([]string{"_id", "firstname", "lastname", "email", "advisorid", "password", "urole",
		"isverified", "isadvisor", "onleave", "parentemail", "age", "haveconcent", "create_date", "update_date"}).AddRow(1, "test", "test", "test@yopmail.com", 1, "fesfsefsef123456", 1,
		true, false, false, "test1@yopmail.com", 30, true, time.Now(), time.Now()))

	req := httptest.NewRequest(http.MethodGet, "/user:/id", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := app.Echo.NewContext(req, rec)
	ctx.QueryParams().Set("email", "test@yopmail.com")
	err = ForgotPassword(app)(auth.AppContext{Context: ctx, ID: 1, RoleId: 2})
	// Assertions
	if assert.NoError(t, err) {
		assert.NoError(t, mock.ExpectationsWereMet())
		assert.Equal(t, http.StatusOK, rec.Code)
	}
}

type Any struct{}

func (a Any) Match(v driver.Value) bool {
	return true
}
