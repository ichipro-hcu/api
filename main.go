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
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/golang-jwt/jwt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// # Structs
// ## Configuration Struct (config.toml)
type Config struct {
	Database         Database
	GoogleOAuth      GoogleOAuth
	JWTSessionConfig JWTSessionConfig
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
	State        string
}

type GooglePeopleAPI struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

type JWTSessionConfig struct {
	Secret string
}

type JWTCallback struct {
	Claims      jwt.MapClaims
	AccessToken string
}

type CoreCookie struct {
	AccessToken string
}

type IsSuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
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

// # Libraries
// ## Authentication
// ### Google Authentication Callback
// -> Generate JWT Token
func googleCallback(state string, code string) (*JWTCallback, error) {
	if state == "" {
		return nil, errors.New("required parameter `state` is missing")
	} else if state != conf.GoogleOAuth.State {
		return nil, errors.New("required parameter `state` is invalid")
	}
	if code == "" {
		return nil, errors.New("required parameter `code` is missing")
	}

	// Exchenge OAuth Token
	cxt := context.Background()
	token, err := oauthConf.Exchange(cxt, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %v", err)
	}
	if token == nil {
		return nil, errors.New("failed to contact with Google API (Could not get token)")
	}

	// Retrieve User Information from Google API
	url := "https://www.googleapis.com/oauth2/v2/userinfo"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.New("failed to contact with Google API (Could not create request)")
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token.AccessToken))

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("failed to contact with Google API (Could not get response)")
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("failed to contact with Google API (Could not read response)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(
			"failed to contact with Google API (Status Code: %d)",
			resp.StatusCode,
		)
	}
	var userDataOnGoogle GooglePeopleAPI
	if err := json.Unmarshal(b, &userDataOnGoogle); err != nil {
		return nil, errors.New("failed to contact with Google API (Could not parse response)")
	}

	claims := jwt.MapClaims{
		"user_id": userDataOnGoogle.ID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtAccessToken, err := jwtToken.SignedString([]byte(conf.JWTSessionConfig.Secret))
	if err != nil {
		return nil,
			fmt.Errorf("failed to generate JWT token: %v", err)
	}

	jwtCallback := &JWTCallback{
		Claims:      claims,
		AccessToken: jwtAccessToken,
	}

	return jwtCallback, nil
}

// ### JWT Token Validation
func JWTTokenValidate(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(conf.JWTSessionConfig.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
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
	state := conf.GoogleOAuth.State
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
	jwtCallback, err := googleCallback(state, code)

	if err == nil {
		// Set Cookie
		c.Cookie(&fiber.Cookie{
			Name:     "accessToken",
			Value:    jwtCallback.AccessToken,
			Path:     "/",
			Expires:  time.Unix(jwtCallback.Claims["exp"].(int64), 0),
			MaxAge:   int(time.Until(time.Unix(jwtCallback.Claims["exp"].(int64), 0)).Seconds()),
			Secure:   true,
			HTTPOnly: true,
		})

		return c.JSON(
			IsSuccessResponse{
				Success: true,
				Message: "Successfully logged in",
			},
		)
	}

	e := err.Error()

	if e == "state string does not match" || e == "required parameter `state` is missing" {
		return c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: e,
			},
		)
	}

	return c.Status(500).JSON(
		IsSuccessResponse{
			Success: false,
			Message: e,
		},
	)
}

// ## Refresh JWT Token Handler
func JWTTokenRefreshHandler(c *fiber.Ctx) error {
	cookie := new(CoreCookie)
	if err := c.CookieParser(cookie); err != nil {
		return c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: "Provided Cookie is invalid",
			},
		)
	}
	if cookie.AccessToken == "" {
		c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: "No token is provided",
			},
		)
	}

	claims, err := JWTTokenValidate(
		cookie.AccessToken,
	)

	if err != nil {
		c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: "Provided token is invalid",
			},
		)
	}

	c.ClearCookie("accessToken")

	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	nToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	nTokenString, err := nToken.SignedString([]byte(conf.JWTSessionConfig.Secret))

	if err != nil {
		c.Status(500).JSON(
			IsSuccessResponse{
				Success: false,
				Message: "Failed to generate new token",
			},
		)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "accessToken",
		Value:    nTokenString,
		Path:     "/",
		Expires:  time.Unix(claims["exp"].(int64), 0),
		MaxAge:   int(time.Until(time.Unix(claims["exp"].(int64), 0)).Seconds()),
		Secure:   true,
		HTTPOnly: true,
	})

	c.JSON(
		IsSuccessResponse{
			Success: true,
			Message: "Successfully refreshed token",
		},
	)

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

	// ## Health Check
	v1.Get("/", healthCheckHandler)
	v1.Get("/check", healthCheckHandler)

	// ## User Scopes
	user := v1.Group("/user")
	// ### Authentication
	user.Get("/auth/login", googleLoginURLHandler)
	user.Get("/auth/callback", googleCallbackHandler)
	user.Get("/auth/refresh", JWTTokenRefreshHandler)

	app.Listen(":3000")
}
