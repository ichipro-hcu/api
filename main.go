package main

import "github.com/gofiber/fiber/v2"

func healthCheckHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
	})
}

func main() {
	app := fiber.New()

	api := app.Group("/api")
	v1 := api.Group("/v1")

	// Health Check
	v1.Get("/", healthCheckHandler)
	v1.Get("/check", healthCheckHandler)

	app.Listen(":3000")
}
