package router

import (
	"context"
	"database/sql"
	"fmt"
	rds "hello/redis"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	//"github.com/gorilla/sessions"
	"github.com/go-redis/redis/v8"
	"github.com/labstack/echo/v4"
)

var ctx = context.Background()
var sended_ch = make(chan bool)
var sended bool = false
var mu sync.Mutex

func timer(db *sql.DB, rdb *redis.Client) error {

	select {
	case <-time.After(time.Duration(GetParams("TIMER") * int(time.Second))):
		mu.Lock()
		defer mu.Unlock()
		switch sended {
		case false:
			err := batchInsertUsers(db, rdb)
			if err != nil {
				return err // Reminder: Check what to do with the error and consider what to do if the batch is blocked. This may lead to the batch function being stalled.
			}
		case true:
			return nil
		}
	case <-sended_ch:
		return nil
	}
	// Return a default error if neither case is satisfied
	return fmt.Errorf("timer function completed without an expected case being hit")

}

func batchInsertUsers(db *sql.DB, rdb *redis.Client) error {
	// Get all user keys from Redis with the prefix "user"
	userKeys, err := rds.GetUserKeys(rdb, "user")
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("Error getting user keys from Redis: %v", err)
	}
	if len(userKeys) > 0 {
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

	// If the key is not found, return 0 or any other default value
	return 0
}

// Routing sets up the routes for the server and initializes the timer
func Routing(server *echo.Echo, psql *sql.DB, rdb *redis.Client) {
	server.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})
	//server.GET("/user", func(c echo.Context) error { return user_update(c, psql, rdb) })
	//server.GET("/users", func(c echo.Context) error { return user_update(c, psql, rdb) })

	server.PUT("/user/id", func(c echo.Context) error { return user_update(c, psql, rdb) })
	server.POST("/user", func(c echo.Context) error { return user_register(c, psql, rdb) })

	/*	server.POST("/batch", func(c echo.Context) error {
		err := batchInsertUsers(psql, rdb)
		if err != nil {
			fmt.Println(err)
			fmt.Println("Error batch")
			return err
		}
		return c.String(http.StatusUnauthorized, "Batch succesfull")
	})*/

}