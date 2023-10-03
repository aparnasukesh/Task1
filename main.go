package main

import (
	"project_instant/config"
	"project_instant/routes"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	config.ConfigDB()

	store := cookie.NewStore([]byte("1011"))
	r.Use(sessions.Sessions("login-session", store))

	routes.RoutesConfig(r, config.DB)
	r.Run(":8080")
}
