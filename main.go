package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/BurntSushi/toml"
	"github.com/gofiber/fiber/v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// # Structs
// ## Configuration Struct (config.toml)
type Config struct {
	Database Database
}

type Database struct {
	User     string
	Password string
	Host     string
	Port     int
	Database string
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

// # Handlers
// ## Health Check Handler
func healthCheckHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
	})
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
	err = initDatabase(conf)
	if err != nil {
		log.Fatalln(err)
	}

	// ## Startup Fiber Application
	app := fiber.New()

	api := app.Group("/api")
	v1 := api.Group("/v1")

	// Health Check
	v1.Get("/", healthCheckHandler)
	v1.Get("/check", healthCheckHandler)

	app.Listen(":3000")
}
