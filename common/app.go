package common

import (
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/afzalabbasi/demo-code/database"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"gopkg.in/go-playground/validator.v9"
)

type App struct {
	*echo.Echo
	DB     *database.DB
	Config Config
}

func NewTestApp() (*App, sqlmock.Sqlmock, error) {
	app := &App{}
	app.Echo = echo.New()
	app.Echo.Validator = &CustomValidator{validator: validator.New()}

	// Set up database
	db, mock, err := sqlmock.New()
	if err != nil {
		return nil, nil, err
	}
	app.DB = &database.DB{DB: sqlx.NewDb(db, "sqlite3")}

	return app, mock, nil
}

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}
