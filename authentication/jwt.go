package authentication 

import (
	"project_instant/models"
	"time"
	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("secret_key")

func GenerateToken(useremail string,userId uint) (string,error){
	claims := &model.Claims{
		Id : userId,
		UserEmail : useremail,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt : jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token :=jwt.NewWithClaims(jwt.SigningMethodHS256,claims)

	return token.SignedString(jwtKey)
}



func ParseToken(tokenString string) (string,error){
	token,err := jwt.ParseWithClaims(tokenString, &model.Claims{}, func(token *jwt.Token) (interface{},error){
		return jwtKey,nil
	})

	if err != nil{
		return "",err
	}

	if claims,ok := token.Claims.(*model.Claims); ok && token.Valid {
		return claims.UserEmail, nil
	}

	return "", err
}