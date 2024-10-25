package router

import (
	"database/sql"
	"fmt"
	postgresdb "hello/postgresdb"
	rds "hello/redis"
	"net/http"

	//"github.com/gorilla/sessions"
	"github.com/go-redis/redis/v8"
	"github.com/labstack/echo/v4"
)

func user_register(c echo.Context, psql *sql.DB, rdb *redis.Client) error {
	fmt.Println("Got post request")
	username := c.FormValue("username")
	password := c.FormValue("password")
	existPsql, err := postgresdb.CheckLoginPsqlExists(psql, username)
	if err != nil {
		return err
	}
	existRedis, err := rds.CheckLoginRedisExists(rdb, username)
	if err != nil {
		return err
	}
	if !existPsql && !existRedis {
		go timer(psql, rdb)
		salt, err := generateSalt(GetParams("SALT_LEN"))
		if err != nil {
			return err
		}
		hashedPassword := hashPassword(password, salt)
		err = rds.AddUser(rdb, username, salt, hashedPassword)
		if err != nil {
			return err
		}
		mu.Lock()
		userCount, err := rds.CheckUserCount(rdb)
		if err != nil {
			return err
		}
		fmt.Println("Got buffer")
		fmt.Println(userCount)
		fmt.Println(int(GetParams("MAX_USER_COUNT_BUFFER")))
		if int(GetParams("MAX_USER_COUNT_BUFFER")) <= userCount {
			err = batchInsertUsers(psql, rdb)
			if err != nil {
				fmt.Println("Error batch")
				return err
			}
			sended = true
			sended_ch <- true
			//Тут стопорится
		}
		mu.Unlock()
		// Тут продалжает свою работу после паузы
		fmt.Println("registered")
		return c.String(http.StatusOK, "User registered")

	} else {
		fmt.Println("exists")
		return c.String(http.StatusConflict, "Username already exists")
	}
}

func user_update(c echo.Context, psql *sql.DB, rdb *redis.Client) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	existRedis, err := rds.CheckLoginRedisExists(rdb, username)
	if err != nil {
		return err
	}
	existPsql, err := postgresdb.CheckLoginPsqlExists(psql, username)
	if err != nil {
		return err
	}
	if existRedis {

		userKey := fmt.Sprintf("user:%s", username)
		salt, err := rdb.HGet(ctx, userKey, "salt").Result()

		if err == redis.Nil {

			return fmt.Errorf("User %s not found", username)

		} else if err != nil {

			return fmt.Errorf("Error retrieving salt from Redis: %v", err)

		}

		saltBytes := []byte(salt)
		hashedPassword := hashPassword(password, saltBytes)
		queriedHashedPassword, err := rdb.HGet(ctx, userKey, "password_hash").Result()

		if err == redis.Nil {
			return fmt.Errorf("Password hash not found for user %s", username)
		} else if err != nil {
			return fmt.Errorf("Error retrieving password hash from Redis: %v", err)
		}

		if queriedHashedPassword == string(hashedPassword) {

			return nil
		}

		return fmt.Errorf("Incorrect password for user %s", username)

	} else if existPsql {
		var salt string
		err := psql.QueryRow("SELECT salt FROM users WHERE username = $1", username).Scan(&salt)
		if err != nil {
			return err
		}
		saltBytes := []byte(salt)
		hashedPassword := hashPassword(password, saltBytes)

		var queriedHashedPassword []byte
		err = psql.QueryRow("SELECT password_hash FROM users WHERE username = $1", username).Scan(&queriedHashedPassword)
		if err != nil {
			return err
		}
		if string(queriedHashedPassword) == string(hashedPassword) {
			return c.String(http.StatusOK, "Authenticated")
		}

	} else {
		return c.String(http.StatusConflict, "Username does not exist")

	}

	return c.String(http.StatusUnauthorized, "Invalid credentials")
}
