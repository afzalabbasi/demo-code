package main

import (
	"encoding/json"
	"flag"
	"github.com/afzalabbasi/demo-code/auth"
	"github.com/afzalabbasi/demo-code/common"
	"github.com/afzalabbasi/demo-code/database"
	"github.com/afzalabbasi/demo-code/handler"
	"github.com/afzalabbasi/demo-code/utils/logger"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/go-playground/validator.v9"
	"log"
	"os"
)

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}

// Attach routes to the app
func initRoutes(app *common.App) {
	// accessible web services will fall in this group
	acc := app.Echo.Group("")
	// restricted web services will fall in this group
	res := app.Echo.Group("/v1")
	// Configure middleware with the custom claims type
	app.Use(middleware.Logger())
	app.Use(middleware.Recover())
	config := middleware.JWTConfig{
		Claims:     &auth.JwtUserClaim{},
		SigningKey: []byte(os.Getenv("JwtSecret")),
	}

	res.Use(middleware.JWTWithConfig(config))
	res.Use(auth.MiddlewareRes)

	//apis route
	acc.POST("/signup", handler.SignUp(app))
	acc.POST("/login", handler.Login(app))
	acc.GET("/confirm", handler.Verify(app))
	acc.GET("/sendforgot", handler.ForgotPassword(app))
	acc.GET("/resetpassword", handler.ResetPassword(app))
	res.PUT("/user/:id", handler.UpdateUser(app))
	res.GET("/user/:id", handler.GetUser(app))
	res.GET("/user", handler.ListUser(app))
}

const defaultConfig = `{
       "database": {
               "driver": "sqlite3",
               "connection": "file:devel.db"
       }
}
`

// @version 1.0
// @host localhost:8080
// @BasePath /v1
func main() {
	// initialize logger
	logger.InitLogger()
	// Parse flags
	addr := flag.String("addr", "localhost:8080", "listen `addr`ess")
	confPath := flag.String("config", "config.json", "config `file`name")
	flag.Parse()

	app := &common.App{}

	// Load config file
	confFile, err := os.Open(*confPath)
	if os.IsNotExist(err) {
		log.Print("Config file does not exist; initializing from default")

		confFile, err = os.Create(*confPath)
		if err != nil {
			log.Fatal(err)
		}

		_, err = confFile.WriteString(defaultConfig)
		if err != nil {
			log.Fatal(err)
		}

		_, err = confFile.Seek(0, 0)
	}
	if err != nil {
		log.Fatal(err)
	}

	err = json.NewDecoder(confFile).Decode(&app.Config)
	confFile.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Set up routes
	app.Echo = echo.New()

	app.Echo.Validator = &CustomValidator{validator: validator.New()}

	app.Echo.Use(middleware.Recover())

	app.Echo.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:  []string{"*"},
		AllowMethods:  []string{echo.GET, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
		ExposeHeaders: []string{"x_auth_token"},
	}))

	initRoutes(app)

	// Set up database
	app.DB, err = database.Connect(app.Config.Database.Driver, app.Config.Database.Connection)
	if err != nil {
		log.Fatal(err)
	}
	err = app.DB.Init()
	if err != nil {
		log.Fatal(err)
	}
	// Start server
	app.Logger.Fatal(app.Start(*addr))
}
