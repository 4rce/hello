package main

import (

	//"hello/postgresdb"
	//postgres "hello/postgresdb"
	psql "hello/postgresdb"
	redis "hello/redis"
	routing "hello/routing"
	"log"

	//"github.com/labstack/gommon/log"

	"github.com/labstack/echo/v4"
	//"github.com/labstack/echo/v4/echoprometheus"
	//"github.com/labstack/echo/v4/middleware.CORSConfig"
)

func main() {
	psqlconn, err := psql.ConnectDB() //fmt.Sprintcould not import github.com/labstack/echo/v4/echoprometheus (no required module provides package "github.com/labstack/echo/v4/echoprometheus")f("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", postgresdb.host, port, user, password, dbname)
	if err != nil {
		//return fmt.Errorf("Error parsing Redis key: %v", err)
	}
	defer psqlconn.Close()
	rdb, err := redis.ConnectRedis()
	if err != nil {
		//return fmt.Errorf("Error parsing Redis key: %v", err)
	}
	defer func() {
		if err := rdb.Close(); err != nil {
			log.Fatalf("Ошибка при закрытии соединения Redis: %v", err)
		}
	}()
	server := echo.New()
	/*server.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		HSTSMaxAge:            9600,
		ContentSecurityPolicy: "default-src 'self'",
		//Skipper:               DefaultSkipper,
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSExcludeSubdomains: true,
	}))
	server.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderXContentTypeOptions},
		AllowMethods: []string{echo.POST, echo.GET, echo.DELETE},
		// 	AllowLanguage: []string{},
		AllowCredentials: true,
		ExposeHeaders:    []string{""},
		MaxAge:           int(86400),
	}))

	today := time.Now().Format("2006-01-02")
	logFileName := fmt.Sprintf("%s.log", today)

	logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		server.Logger.Fatalf("Error opening log file: %v", err)
	}
	defer logFile.Close()

	server.AutoTLSManager.HostPolicy = autocert.HostWhitelist(os.Getenv("DOMAIN"))
	server.AutoTLSManager.Cache = autocert.DirCache("/etc/letsencrypt/live/" + os.Getenv("DOMAIN") + "/")
	server.Use(echoprometheus.NewMiddleware("myapp"))
	mwConfig := echoprometheus.MiddlewareConfig{
		Skipper: func(c echo.Context) bool {
			return strings.HasPrefix(c.Path(), "/testurl")
		}, // does not gather metrics metrics on routes starting with `/testurl`
	}
	server.Debug = true
	server.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method}, uri=${uri}, status=${status}\n",
		Output: logFile,
	}))
	server.Use(echoprometheus.NewMiddlewareWithConfig(mwConfig))
	server.GET("/metrics", echoprometheus.NewHandler())*/
	routing.Routing(server, psqlconn, rdb)
	server.Logger.Fatal(server.Start(":1323"))

}
