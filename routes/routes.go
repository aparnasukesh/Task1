package routes

import (
	"project_instant/authentication"
	"project_instant/config"
	"project_instant/handlers"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func RoutesConfig(r *gin.Engine, db *gorm.DB) {
	authMiddleware := authentication.Authenticate()
	r.Static("/static", "./static")
	r.LoadHTMLGlob("templates/*.html")
	r.Use(authentication.ClearCache())

	authGroup := r.Group("/au")
	authGroup.Use(config.DatabaseMiddleware(db))
	{
		authGroup.GET("/login", handlers.LoginPage)
		authGroup.GET("/signup", handlers.SignupPage)
		authGroup.POST("/login", handlers.LoginAuthentication)
		authGroup.POST("/signup", handlers.SignupForm)
	}

	protectedGroup := r.Group("/pr")
	protectedGroup.Use(authMiddleware)
	protectedGroup.Use(config.DatabaseMiddleware(db))
	{
		protectedGroup.GET("/home", handlers.HomePage)
		protectedGroup.GET("/logout", handlers.Logout)
	}

	adminGroup := r.Group("/su")
	adminGroup.Use(authentication.AdminAuthentication())

	r.GET("/admin-login", handlers.AdminLoginPage)
	r.POST("/admin-login", handlers.AdminAuthentication)
	{
		adminGroup.GET("/admin-panel", handlers.AdminPanel)
		adminGroup.GET("adminlogout", handlers.AdminLogout)
		adminGroup.POST("/adduser", handlers.AddNewUser)
		adminGroup.GET("/search", handlers.SearchUser)
		adminGroup.POST("/edituser/:id", handlers.EditUser)
		adminGroup.GET("/deleteuser/:id", handlers.DeleteUser)
	}
}
