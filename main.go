package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// # Structs
// ## Configuration Struct (config.toml)
type Config struct {
	Database    Database
	GoogleOAuth GoogleOAuth
}

type Database struct {
	User     string
	Password string
	Host     string
	Port     int
	Database string
}

type GoogleOAuth struct {
	ClientId     string
	ClientSecret string
	RedirectUri  string
}

type GooglePeopleAPI struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

// # Initializations
// ## Parse Configuration
var conf Config

func initConfiguration(confPath string) error {
	_, err := toml.DecodeFile(confPath, &conf)
	if err != nil {
		return err
	}
	return nil
}

// ## Connect to Database
var Core *gorm.DB

func initDatabase(config Config) error {
	var err error

	dsnCore := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s",
		config.Database.User,
		config.Database.Password,
		config.Database.Host,
		config.Database.Port,
		config.Database.Database,
	)

	Core, err = gorm.Open(postgres.Open(dsnCore), &gorm.Config{
		PrepareStmt: true,
	})

	if err != nil {
		return err
	}

	return nil
}

var oauthConf *oauth2.Config

func initOAuth() {
	oauthConf = &oauth2.Config{
		ClientID:     conf.GoogleOAuth.ClientId,
		ClientSecret: conf.GoogleOAuth.ClientSecret,
		RedirectURL:  conf.GoogleOAuth.RedirectUri,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

// # Handlers
// ## Health Check Handler
func healthCheckHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
	})
}

// ## Google OAuth Login URL Handler
func googleLoginURLHandler(c *fiber.Ctx) error {
	state := "random"
	url := oauthConf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return c.JSON(fiber.Map{
		"url": url,
	})
}

// ## Google OAuth Callback Handler
func googleCallbackHandler(c *fiber.Ctx) error {
	// Get Callback Query Params
	state := c.Query("state")
	code := c.Query("code")

	if state == "" {
		return errors.New("required parameter `state` is missing")
	} else if state != "random" {
		return errors.New("required parameter `state` is invalid")
	}
	if code == "" {
		return errors.New("required parameter `code` is missing")
	}

	// Exchenge OAuth Token
	cxt := context.Background()
	token, err := oauthConf.Exchange(cxt, code)
	if err != nil {
		return fmt.Errorf("failed to exchange token: %v", err)
	}
	if token == nil {
		return errors.New("failed to contact with Google API (Could not get token)")
	}

	// Retrieve User Information from Google API
	url := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.New("failed to contact with Google API (Could not create request)")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token.AccessToken))

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("failed to contact with Google API (Could not get response)")
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.New("failed to contact with Google API (Could not read response)")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf(
			"failed to contact with Google API (Status Code: %d)",
			resp.StatusCode,
		)
	}
	var userDataOnGoogle GooglePeopleAPI
	if err := json.Unmarshal(b, &userDataOnGoogle); err != nil {
		return errors.New("failed to contact with Google API (Could not parse response)")
	}

	c.JSON(userDataOnGoogle)
	return nil
}

// # Application
func main() {
	// # Initializations
	// ## Database Connection
	confPath := ""
	flag.StringVar(&confPath, "config", "./config.toml", "Configuration file path")
	flag.Parse()

	err := initConfiguration(confPath)
	if err != nil {
		log.Fatalln(err)
	}

	// if Arg `no-database` is used, then skip database connection process.
	if !slices.Contains(os.Args, "no-database-flag") {
		err = initDatabase(conf)
		if err != nil {
			log.Fatalln(err)
		}
	}

	initOAuth()

	// ## Startup Fiber Application
	app := fiber.New()

	api := app.Group("/api")
	v1 := api.Group("/v1")

	// Health Check
	v1.Get("/", healthCheckHandler)
	v1.Get("/check", healthCheckHandler)

	// User Scopes
	user := v1.Group("/user")
	user.Get("/auth/login", googleLoginURLHandler)
	user.Get("/auth/callback", googleCallbackHandler)

	app.Listen(":3000")
}
