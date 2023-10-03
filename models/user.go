package model

import (
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)


type Credentials struct {
	gorm.Model	
	Username  string				`json:"name"`
	Email     string				`json:"email"`
	Password  string				`json:"password"`
}

type Claims struct{
	Id uint         `json:"id"`
	UserEmail string  `json:"useremail"`
	jwt.RegisteredClaims
}