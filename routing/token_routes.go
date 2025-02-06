package router

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Claims struct {
	Username   string `json:"username"`
	UserAgent  string `json:"user_agent"`
	DeviceType string `json:"device_type"`
	jwt.RegisteredClaims
}

var mySigningKey = []byte(os.Getenv("JWT_SECRET"))

func createToken(username, userAgent, deviceType string) (string, error) {
	claims := Claims{
		Username:   username,
		UserAgent:  userAgent,
		DeviceType: deviceType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 168)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(mySigningKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func parseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return mySigningKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
}

// func main() {
// 	username := "john_doe"
// 	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
// 	deviceType := "Desktop"

// 	token, err := createToken(username, userAgent, deviceType)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fmt.Println("Generated Token:", token)

// 	// Пример проверки токена
// 	claims, err := parseToken(token)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fmt.Printf("Username: %s, User-Agent: %s, Device Type: %s, Roles: %v\n", claims.Username, claims.UserAgent, claims.DeviceType)
// }
