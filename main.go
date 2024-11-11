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
	"github.com/gofiber/fiber/v2/middleware/cors"
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
	Success bool        `json:"success"`
	Message *string     `json:"message,omitempty"`
	Result  interface{} `json:"result,omitempty"`
}

// ## User Struct
type User struct {
	ID        string `gorm:"primaryKey"`
	Email     string
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
	Alias     string    `gorm:"unique"`
	IsExist   bool      `gorm:"default:true"`
	AvatarURL string    `gorm:"default:null"`
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

	if slices.Contains(os.Args, "init-database-flag") {
		err = Core.AutoMigrate(
			&User{},
		)
		if err != nil {
			return err
		}
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
		"email":   userDataOnGoogle.Email,
		"picture": userDataOnGoogle.Picture,
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

// ## User
// ### Create User
func createUser(id string, email string, avatarUrl string) (*User, error) {
	user := &User{
		ID:        id,
		Email:     email,
		Alias:     string(id),
		AvatarURL: avatarUrl,
	}
	result := Core.Create(user)
	if result.Error != nil {
		return nil, result.Error
	}
	return user, nil
}

func ReadUser(id string, email string, avatarUrl string) (*User, error) {
	user := &User{}
	result := Core.First(user, "id = ?", id)
	if result.Error == gorm.ErrRecordNotFound {
		return createUser(id, email, avatarUrl)
	} else if result.Error != nil {
		return nil, result.Error
	} else if !user.IsExist {
		return nil, errors.New("User is not exist")
	}
	return user, nil
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
	return c.Status(303).Redirect(url)
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
			SameSite: "Lax",
			Domain:   ".sasakulab.com",
			HTTPOnly: true,
		})
		return c.Status(303).Redirect("https://ichipro.sasakulab.com/me")
	}

	e := err.Error()

	if e == "state string does not match" || e == "required parameter `state` is missing" {
		return c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &e,
			},
		)
	}

	return c.Status(500).JSON(
		IsSuccessResponse{
			Success: false,
			Message: &e,
		},
	)
}

// ## Refresh JWT Token Handler
func JWTTokenRefreshHandler(c *fiber.Ctx) error {
	cookie := new(CoreCookie)
	if err := c.CookieParser(cookie); err != nil {
		msg := "Provided Cookie is invalid"
		return c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
	}
	if cookie.AccessToken == "" {
		msg := "No token is provided"
		return c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
	}

	claims, err := JWTTokenValidate(
		cookie.AccessToken,
	)

	if err != nil {
		msg := "Provided token is invalid"
		c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
	}

	c.ClearCookie("accessToken")

	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	nToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	nTokenString, err := nToken.SignedString([]byte(conf.JWTSessionConfig.Secret))

	if err != nil {
		msg := "Failed to generate new token"
		c.Status(500).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
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

	msg := "Successfully refreshed token"
	return c.JSON(
		IsSuccessResponse{
			Success: true,
			Message: &msg,
		},
	)
}

// ## User
// ### Get User Handler
func ParseCookie(c *fiber.Ctx) (*string, *string, *string, error) {
	cookie := new(CoreCookie)
	if err := c.CookieParser(cookie); err != nil {
		msg := "Provided Cookie is invalid"
		c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
		return nil, nil, nil, err
	}
	if cookie.AccessToken == "" {
		msg := "No token is provided"
		c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
		return nil, nil, nil, errors.New(msg)
	}

	claims, err := JWTTokenValidate(
		cookie.AccessToken,
	)

	if err != nil {
		msg := "Provided token is invalid"
		c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
		return nil, nil, nil, err
	}

	claims_id := claims["user_id"].(string)
	claims_email := claims["email"].(string)
	claims_avatar := claims["picture"].(string)
	if claims_id == "" {
		msg := "Failed to parse user id from claims"
		c.Status(400).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
		return nil, nil, nil, errors.New(msg)
	}
	return &claims_id, &claims_email, &claims_avatar, nil
}

func getUserHandler(c *fiber.Ctx) error {
	claims_id, claims_email, claims_avatar, err := ParseCookie(c)
	if err != nil {
		msg := "Failed to retrieve user information (Cookie Parse Error)"
		return c.Status(500).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
	}

	user, err := ReadUser(*claims_id, *claims_email, *claims_avatar)
	if err != nil {
		msg := "Failed to retrieve user information"
		return c.Status(500).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
	}

	c.Status(200).JSON(
		IsSuccessResponse{
			Success: true,
			Result:  &user,
		},
	)
	return nil
}

func deleteUserHandler(c *fiber.Ctx) error {
	claims_id, _, _, err := ParseCookie(c)
	if err != nil {
		msg := "Failed to retrieve user information"
		return c.Status(500).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
	}

	user := &User{}
	result := Core.Model(user).Where("id = ?", *claims_id).Update("is_exist", false)
	if result.Error != nil {
		msg := "Failed to delete user"
		return c.Status(500).JSON(
			IsSuccessResponse{
				Success: false,
				Message: &msg,
			},
		)
	}

	msg := "Successfully deleted user"
	return c.JSON(
		IsSuccessResponse{
			Success: true,
			Message: &msg,
		},
	)
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

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost.sasakulab.com:5173, https://ichipro.sasakulab.com, http://localhost:5173",
		AllowHeaders:     "Origin, Content-Type, Accept",
		AllowCredentials: true,
	}))

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

	// ### User Information
	user.Get("/me", getUserHandler)
	user.Delete("/me", deleteUserHandler)

	app.Listen(":3000")
}
