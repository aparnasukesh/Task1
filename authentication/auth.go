package authentication

import (
	"net/http"
	"project_instant/config"
	"project_instant/models"

	"github.com/gin-gonic/gin"
)


func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("jwtToken")
		if err != nil || token == "" {
			c.Redirect(http.StatusSeeOther,"/au/login")
			c.Abort()
			return
		}

		useremail, err := ParseToken(token)
		if err != nil || useremail == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		}

		user, err := GetUserByUserEmail(useremail)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"}) 
		}
		c.Set("email",useremail)
		c.Set("user", user)

		c.Next()
	}
}


func AdminAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenCookie, err := c.Cookie("Admin")
		if err != nil || tokenCookie == "" {
					c.Redirect(http.StatusSeeOther, "/admin-login") 
					return
		}
		useremail, err := ParseToken(tokenCookie)
			if err != nil || useremail == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
			}

			if useremail!="element@yahoo.com" {
				c.Redirect(http.StatusSeeOther, "/admin-login") 
				return
			}

		c.Next()
	}
}



func GetUserByUserEmail(email string) (*model.Credentials, error) {
	var user model.Credentials
	if err := config.DB.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}


func ClearCache() gin.HandlerFunc{
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		c.Next()
	}
}