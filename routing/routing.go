package router

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	postgresdb "hello/postgresdb"
	rds "hello/redis"
	"net/http"
	"os"
	"strconv"

	"sync"
	"time"

	//"github.com/gorilla/sessions"
	"github.com/go-redis/redis/v8"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/argon2"
)

var ctx = context.Background()
var sended_ch = make(chan bool)
var sended bool = false
var mu sync.Mutex

func timer(db *sql.DB, rdb *redis.Client) {

	select {

	case <-time.After(time.Duration(GetParams("TIMER") * int(time.Second))):
		mu.Lock()
		defer mu.Unlock()
		switch sended {
		case false:
			err := batchInsertUsers(db, rdb)
			if err != nil {
				// Напоминание: Глянуть что делать с ошибкой и посмотреть что делать в случае если батч будет заблокирован. Это может привести к блоку функции батч.
			}
		case true:
			return
		}
	case <-sended_ch:
		return
	}

}

func batchInsertUsers(db *sql.DB, rdb *redis.Client) error {
	// Get all user keys from Redis with the prefix "user"
	userKeys, err := rds.GetUserKeys(rdb, "user")
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("Error getting user keys from Redis: %v", err)
	}

	// Initialize SQL query for inserting users
	query := "INSERT INTO users (username, password_hash, salt) VALUES "
	values := []interface{}{}

	// Iterate over each user key
	for i := 0; i < len(userKeys); i++ {
		// Get user data from Redis for each key
		user, err := rds.GetRedisData(rdb, userKeys[i])
		if err != nil {
			return fmt.Errorf("Error getting user data from Redis: %v", err)
		}

		// Parse the Redis key to extract the username (login)
		login, err := rds.ParseIdRedis(userKeys[i])
		if err != nil {
			return fmt.Errorf("Error parsing Redis key: %v", err)
		}

		// Add parameters to the SQL query for each user (username, password_hash, salt)
		query += fmt.Sprintf("($%d, $%d, $%d)", 3*i+1, 3*i+2, 3*i+3)
		if i < len(userKeys)-1 {
			query += ", " // Add comma between rows, except for the last one
		}

		// Append the values to the list for insertion (login, password_hash, salt)
		values = append(values, login, user["password_hash"], user["salt"])
	}

	// Execute the batch insert query with all the collected values
	fmt.Println(query)
	fmt.Println(values)
	_, err = db.Exec(query, values...)
	if err != nil {
		return fmt.Errorf("Error executing SQL insert: %v", err)
	}
	for i := 0; i < len(userKeys); i++ {
		err := rdb.Del(ctx, userKeys[i]).Err()
		if err != nil {
			return fmt.Errorf("Deleting rds data %v", err)
		}
	}

	// Return nil if no errors occur
	return err
}

// GetParams retrieves configuration parameters for various settings
func GetParams(param string) int {
	defaultCount := map[string]int{
		"ENC_MEMORY":            64,  // Minimum amount of memory in MB (64 MB is the lowest usable value)
		"ENC_THREADS":           2,   // Minimum number of threads (recommended to be at least 2 for multi-threading)
		"ENC_TIME":              3,   // Minimum number of iterations (more than 2 provides some protection)
		"ENC_KEYLEN":            32,  // Minimum length of the hash (recommended to be at least 32 bytes for security)
		"MAX_USER_COUNT_BUFFER": 100, // Maximum number of users whose data will be stored in Redis before being sent to the database
		"TIMER":                 60,  // Timer
		"SALT_LEN":              16,
	}
	env := os.Getenv(param)
	if env != "" {
		value, err := strconv.Atoi(env)
		if err == nil {
			return value
		}
	}
	if defaultValue, ok := defaultCount[param]; ok {
		return defaultValue
	}

	// Если ключ не найден, возвращаем 0 или любое другое значение по умолчанию
	return 0
}

// generateSalt generates a random salt of the given length
func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// hashPassword hashes the provided password with the given salt using Argon2
func hashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt,
		uint32(GetParams("ENC_TIME")), uint32(GetParams("ENC_MEMORY")), uint8(GetParams("ENC_THREADS")), uint32(GetParams("ENC_KEYLEN")))
}

// Routing sets up the routes for the server and initializes the timer
func Routing(server *echo.Echo, psql *sql.DB, rdb *redis.Client) {
	//dataPushTimer := NewTimer(time.Duration(GetParams("TIMER"))*time.Second, psql, rdb)
	server.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})

	server.POST("/set", func(c echo.Context) error {
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
		if existPsql {
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

		} else if existRedis {

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

		} else {
			return c.String(http.StatusConflict, "Username does not exist")

		}

		return c.String(http.StatusUnauthorized, "Invalid credentials")
	})

	server.POST("/users", func(c echo.Context) error {
		fmt.Println("Got post request")
		username := c.FormValue("username")
		password := c.FormValue("password")

		fmt.Println("Request from Psql")
		existPsql, err := postgresdb.CheckLoginPsqlExists(psql, username)
		fmt.Println("Got from Psql")
		if err != nil {
			fmt.Println("Error psql")
			fmt.Println(err)
			return err
		}
		fmt.Println("Request from Redis")
		existRedis, err := rds.CheckLoginRedisExists(rdb, username)
		fmt.Println("Got from Redis")
		if err != nil {
			fmt.Println("Error rds")
			fmt.Println(err)
			return err
		}
		fmt.Println(existRedis)
		fmt.Println(existPsql)
		if !existPsql && !existRedis {
			fmt.Println("There is a timer")
			//Тут запукается таймер
			go timer(psql, rdb)
			salt, err := generateSalt(GetParams("SALT_LEN"))
			if err != nil {
				fmt.Println("Error salt")
				return err
			}
			hashedPassword := hashPassword(password, salt)
			err = rds.AddUser(rdb, username, salt, hashedPassword)
			if err != nil {
				fmt.Println("Error")
				return err
			}
			//Тут он становиться на паузу
			fmt.Println("There is a pause")
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
	})
	/*server.POST("/batch", func(c echo.Context) error {
		err := batchInsertUsers(psql, rdb)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Error batch")
			return err
		}
		return c.String(http.StatusUnauthorized, "Invalid credentials")
	})*/

}
