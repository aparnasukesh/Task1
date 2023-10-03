package handlers

import (
	"net/http"
	"project_instant/authentication"
	"project_instant/config"
	model "project_instant/models"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func LoginPage(c *gin.Context) {
	tokenCookie, err := c.Cookie("jwtToken")
	if err == nil && tokenCookie != "" {
		c.Redirect(http.StatusSeeOther, "/pr/home")
		return
	}
	c.HTML(http.StatusOK, "login.html", nil)
}

func SignupPage(c *gin.Context) {
	tokenCookie, err := c.Cookie("jwtToken")
	if err == nil && tokenCookie != "" {
		c.Redirect(http.StatusSeeOther, "/pr/home")
		return
	}
	c.HTML(http.StatusOK, "signup.html", nil)
}

func LoginAuthentication(c *gin.Context) {
	var temp struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	temp.Email = c.PostForm("email")
	temp.Password = c.PostForm("password")

	user, err := authentication.GetUserByUserEmail(temp.Email)
	if err != nil {
		c.HTML(http.StatusNotFound, "login.html", gin.H{"error": "User not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(temp.Password)); err == nil {
		token, err := authentication.GenerateToken(user.Email, user.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		cookie := http.Cookie{
			Name:     "jwtToken", // Cookie name
			Value:    token,      // JWT token value
			Path:     "/",        // Cookie path (root)
			HttpOnly: true,       // The cookie is accessible only through HTTP
			Secure:   false,      // Set to true in production for HTTPS
			SameSite: http.SameSiteStrictMode,
			MaxAge:   36000, //seconds
		}
		http.SetCookie(c.Writer, &cookie)

		c.Redirect(http.StatusSeeOther, "/pr/home")
	} else {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"error": "Invalid credentials",
		})
	}

}

func SignupForm(c *gin.Context) {
	db := c.MustGet("db").(*gorm.DB)
	var user model.Credentials

	user.Username = c.PostForm("name")
	user.Email = c.PostForm("email")
	password := c.PostForm("password")
	c_password := c.PostForm("c_password")

	if user.Username == "" || user.Email == "" || password == "" {
		c.HTML(http.StatusConflict, "signup.html", gin.H{"error": "Please fill all the details"})
		return
	}

	var existingUser model.Credentials
	if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		c.HTML(http.StatusConflict, "signup.html", gin.H{"error": "Email already in use"})
		return
	} else if err != gorm.ErrRecordNotFound {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if password != c_password {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "password mismatch"})
		return
	}
	//hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)

	//store it in db
	db.Create(&user)

	// continue to login
	c.HTML(200, "login.html", gin.H{
		"message": "Signup success, Login to continue",
	})
}

func HomePage(c *gin.Context) {
	tokenCookie, err := c.Cookie("jwtToken")
	if err != nil || tokenCookie == "" {
		c.Redirect(http.StatusSeeOther, "/au/login")
		return
	}
	data, _ := c.Get("email")
	user := data.(string)
	c.HTML(http.StatusOK, "home.html", gin.H{
		"email": user,
	})
}

func Logout(c *gin.Context) {
	// clear the token
	c.SetCookie("jwtToken", "", -1, "/", "", false, true)
	//redirect to login page
	c.Redirect(http.StatusSeeOther, "/au/login")
}

//AAAAAAAAAAAAAADDDDDDDDMMMMMMMIIIIIIIIIIIINNNNNNNNNN PPPPPPPPPAAAAAAAAAANNNNNNNNNEEEEEEEELLLLLLLLLLLL

func AdminLoginPage(c *gin.Context) {
	tokenCookie, err := c.Cookie("Admin")
	if err == nil && tokenCookie != "" {
		c.Redirect(http.StatusSeeOther, "/su/admin-panel")
		return
	}
	c.HTML(http.StatusOK, "admin-login.html", nil)
}

func AdminAuthentication(c *gin.Context) {
	username := c.PostForm("admin")
	password := c.PostForm("password")

	if username != "aparnasukesh@gmail.com" || password != "12345" {
		c.HTML(http.StatusUnauthorized, "admin-login.html", gin.H{"error": "Invalid credentials"})

	}
	token, err := authentication.GenerateToken(username, 1)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	cookie := http.Cookie{
		Name:     "Admin", // Cookie name
		Value:    token,   // JWT token value
		Path:     "/",     // Cookie path (root)
		HttpOnly: true,    // The cookie is accessible only through HTTP
		Secure:   false,   // Set to true in production for HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   36000, //seconds
	}
	http.SetCookie(c.Writer, &cookie)

	c.Redirect(http.StatusSeeOther, "/su/admin-panel")
}

func AdminPanel(c *gin.Context) {

	var temp_user []model.Credentials
	result := config.DB.Find(&temp_user)

	if result.Error != nil {
		c.Redirect(http.StatusSeeOther, "/admin-login")
	} else {
		c.HTML(http.StatusOK, "adminpanel.html", gin.H{
			"temp_user": temp_user,
		})
		return
	}
	c.HTML(http.StatusOK, "adminpanel.html", nil)

}

func AdminLogout(c *gin.Context) {
	c.SetCookie("Admin", "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin-login")
}

func AddNewUser(c *gin.Context) {
	var user model.Credentials

	user.Username = c.PostForm("name")
	user.Email = c.PostForm("email")
	user.Password = c.PostForm("password")

	config.DB.Create(&user)
	c.Redirect(http.StatusSeeOther, "/su/admin-panel")
}

func SearchUser(c *gin.Context) {
	search_uname := c.Query("query")
	var temp_user []model.Credentials
	result := config.DB.Where("username ILIKE ?", "%"+search_uname+"%").Find(&temp_user)
	if result.Error != nil {
		c.Redirect(http.StatusSeeOther, "/su/admin-panel")

	} else {
		c.HTML(http.StatusOK, "adminpanel.html", gin.H{
			"temp_user": temp_user,
		})

	}

}

func EditUser(c *gin.Context) {
	id := c.Param("id")
	var user model.Credentials
	if err := config.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.Username = c.PostForm("name")
	user.Email = c.PostForm("email")
	user.Password = c.PostForm("password")

	config.DB.Save(&user)
	c.Redirect(http.StatusSeeOther, "/su/admin-panel")
}

func DeleteUser(c *gin.Context) {
	id := c.Param("id")
	var user model.Credentials
	if err := config.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}
	config.DB.Delete(&user)
	c.Redirect(http.StatusSeeOther, "/su/admin-panel")
}
