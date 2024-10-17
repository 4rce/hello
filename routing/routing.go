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

	//"sync"
	//"time"

	//"github.com/gorilla/sessions"
	"github.com/go-redis/redis/v8"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/argon2"
)

var ctx = context.Background()

func batchInsertUsers(db *sql.DB, rdb *redis.Client) error {
	// Get all user keys from Redis with the prefix "user"
	userKeys, err := rds.GetUserKeys(rdb, "user")
	if err != nil {
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
	_, err = db.Exec(query, values...)
	if err != nil {
		return fmt.Errorf("Error executing SQL insert: %v", err)
	}
	for i := 0; i < len(userKeys); i++ {
		err := rdb.Del(ctx, userKeys[i]).Err()
		if err != nil {
			return fmt.Errorf("Error executing SQL insert: %v", err)
		}
	}

	// Return nil if no errors occur
	return err
}

// GetParams retrieves configuration parameters for various settings
func GetParams(param string) int {
	defaultCount := map[string]int{
		"MEMORY":                64,  // Minimum amount of memory in MB (64 MB is the lowest usable value)
		"THREADS":               2,   // Minimum number of threads (recommended to be at least 2 for multi-threading)
		"TIME":                  3,   // Minimum number of iterations (more than 2 provides some protection)
		"KEYLEN":                32,  // Minimum length of the hash (recommended to be at least 32 bytes for security)
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
	return defaultCount[param]
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
		uint32(GetParams("TIME")), uint32(GetParams("MEMORY")), uint8(GetParams("THREADS")), uint32(GetParams("KEYLEN")))
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

		if !existPsql || !existRedis {
			//Тут запукается таймер
			salt, err := generateSalt(GetParams("SALT_LEN"))
			if err != nil {
				return err
			}
			hashedPassword := hashPassword(password, salt)
			err = rds.AddUser(rdb, username, salt, hashedPassword)
			if err != nil {
				return err
			}
			//Тут он становиться на паузу
			userCount, err := rds.CheckUserCount(rdb)
			if err != nil {
				return err
			}
			if GetParams("MAX_USER_COUNT_BUFFER") >= userCount {
				//dataPushTimer.Stop()
				err = batchInsertUsers(psql, rdb)
				if err != nil {
					return err
				}
				//Тут стопорится
			}
			// Тут продалжает свою работу после паузы
			return c.String(http.StatusOK, "User registered")

		} else {
			return c.String(http.StatusConflict, "Username already exists")
		}
	})
}
