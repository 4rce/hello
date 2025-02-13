package router

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	postgresdb "hello/postgresdb"
	rds "hello/redis"
	"net/http"

	"github.com/go-redis/redis/v8"
	"github.com/labstack/echo/v4"
)

func checkRdsUserPermission(ctx context.Context, rdb *redis.Client, username string, password string) (bool, error) {
	userKey := fmt.Sprintf("user:%s", username)
	user, err := rds.GetRedisData(rdb, userKey)

	if err == redis.Nil {
		return false, fmt.Errorf("User not found")
	} else if err != nil {
		return false, fmt.Errorf("Error retrieving user data from Redis: %v", err)
	}

	saltBytes := []byte(user["salt"])
	hashedPassword := hashPassword(password, saltBytes)
	if bytes.Equal(hashedPassword, []byte(user["password_hash"])) {
		return true, nil
	} else {
		return false, fmt.Errorf("Password not correct")
	}
}

func checkPsqlUserPermission(ctx context.Context, db *sql.DB, username string, password string) (bool, error) {
	// Query to get the salt and password hash from the database
	var salt string
	var passwordHash string

	query := "SELECT salt, password_hash FROM users WHERE username = $1"
	err := db.QueryRow(query, username).Scan(&salt, &passwordHash)

	// Check if the user exists
	if err == sql.ErrNoRows {
		return false, fmt.Errorf("User not found")
	} else if err != nil {
		return false, fmt.Errorf("Error retrieving user data from PostgreSQL: %v", err)
	}

	// Check the password hash
	saltBytes := []byte(salt)
	hashedPassword := hashPassword(password, saltBytes)
	if bytes.Equal(hashedPassword, []byte(passwordHash)) {
		return true, nil
	} else {
		return false, fmt.Errorf("Password not correct")
	}
}

func user_register(c echo.Context, psql *sql.DB, rdb *redis.Client) error {

	chSended := make(chan bool)
	chErrorPsql := make(chan error, 1)
	chErrorRedis := make(chan error, 1)
	chExistPsql := make(chan bool, 1)
	chExistRedis := make(chan bool, 1)
	chErrorTimer := make(chan error)

	fmt.Println("Got post request")
	username := c.FormValue("username")
	password := c.FormValue("password")
	mu.Lock()
	go func() {
		existPsql, err := postgresdb.CheckLoginPsqlExists(psql, username)
		chExistPsql <- existPsql
		chErrorPsql <- err

	}()
	go func() {
		existRedis, err := rds.CheckLoginRedisExists(rdb, username)
		chExistRedis <- existRedis
		chErrorRedis <- err
	}()
	if err := <-chErrorPsql; err != nil {
		return c.String(http.StatusInternalServerError, "Error checking PostgreSQL: "+err.Error())
	}

	if err := <-chErrorRedis; err != nil {
		return c.String(http.StatusInternalServerError, "Error checking Redis: "+err.Error())
	}

	existPsql := <-chExistPsql
	existRedis := <-chExistRedis
	mu.Unlock() //Check if a mutex is needed here, as there might be an issue with the delay where the record could be added while we are checking to ensure there are no such records.
	if !existPsql && !existRedis {
		go timer(chErrorTimer, chSended, psql, rdb)
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
		if int(GetParams("MAX_USER_COUNT_BUFFER")) <= userCount {
			err = batchInsertUsers(psql, rdb)
			if err != nil {
				fmt.Println("Error batch")
				return err
			}
			chSended <- true
		}
		mu.Unlock()
		fmt.Println("registered")
		return c.String(http.StatusOK, "User registered")

	} else {
		fmt.Println("exists")
		return c.String(http.StatusConflict, "Username already exists")
	}
}

// Тут бога нет, есть только две го рутины и один return.
func user_update(c echo.Context, psql *sql.DB, rdb *redis.Client) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	new_password := c.FormValue("new_password")
	ctx := c.Request().Context()
	ch := make(chan bool) // Channel for communication between goroutines
	chError := make(chan error)
	chPsqlReturn := make(chan error)
	chRedisReturn := make(chan error)
	mu.Lock()
	// Check if the user exists in PostgreSQL
	go func() {
		existPsql, err := postgresdb.CheckLoginPsqlExists(psql, username)
		if err != nil {
			chPsqlReturn <- c.String(http.StatusConflict, "Error checking PostgreSQL permissions")
			chError <- err
			fmt.Println("Error:", err)
			return
		}
		chError <- err
		ch <- existPsql
		if existPsql {
			// Check user permissions in PostgreSQL
			userPermission, err := checkPsqlUserPermission(ctx, psql, username, password)
			if err != nil {
				chPsqlReturn <- c.String(http.StatusConflict, "Error checking PostgreSQL permissions")
				fmt.Println("Error:", err)
				return
			}
			if !userPermission {
				chPsqlReturn <- c.String(http.StatusConflict, "No permission")
				return
			}

			// Generate salt for the new password
			salt := []byte{}
			salt, err = generateSalt(GetParams("SALT_LEN"))
			if err != nil {
				chPsqlReturn <- c.String(http.StatusConflict, "Error with saving the password.")
				fmt.Println("Error:", err)
				return
			}

			// Hash the new password
			hashedPassword := hashPassword(new_password, salt)

			// Update user data in PostgreSQL
			query := "UPDATE users SET password_hash = $1, salt = $2 WHERE username = $3"
			_, err = psql.Exec(query, hashedPassword, salt, username)
			if err != nil {
				fmt.Println("Error:", err)
				chPsqlReturn <- c.String(http.StatusConflict, "Error with saving the password.")
				return
			}

			// Send success message
			chPsqlReturn <- c.String(http.StatusOK, "User updated in PostgreSQL and cleared from Redis")
		}
	}()

	// Check if the user exists in Redis
	go func() {
		// Check if the user exists in Redis
		existRedis, err := rds.CheckLoginRedisExists(rdb, username)
		if err != nil {
			chRedisReturn <- c.String(http.StatusConflict, "Error checking PostgreSQL permissions")
			fmt.Println("Error:", err)
			return
		}
		// Get the existence status from PostgreSQL via the channel
		errorPsql := <-chError
		if errorPsql != nil {
			chRedisReturn <- c.String(http.StatusConflict, "Error with saving the password.")
			return
		}
		existPsql := <-ch
		if existRedis && existPsql {
			if err := rdb.Del(ctx, fmt.Sprintf("user:%s", username)).Err(); err != nil {
				chRedisReturn <- c.String(http.StatusConflict, fmt.Sprintf("Error deleting user data from Redis: %v", err))
				return
			}
		} else if existRedis && !existPsql {
			// Check user permissions in Redis
			userPermission, err := checkRdsUserPermission(ctx, rdb, username, password)
			if err != nil {
				chRedisReturn <- c.String(http.StatusConflict, "Error checking Redis permissions")
				return
			}
			if !userPermission {
				chRedisReturn <- c.String(http.StatusConflict, "No permission")
				return
			}
			// Get user data from Redis
			userData, err := rds.GetRedisData(rdb, fmt.Sprintf("user:%s", username))
			if err != nil {
				chRedisReturn <- c.String(http.StatusInternalServerError, fmt.Sprintf("Error getting user data from Redis: %v", err))
				return
			}

			// Hash the new password
			hashedPassword := hashPassword(new_password, []byte(userData["salt"]))

			// Update user data in Redis
			if err := rdb.HSet(ctx, fmt.Sprintf("user:%s", username), map[string]interface{}{
				"password_hash": string(hashedPassword),
				"salt":          userData["salt"],
			}).Err(); err != nil {
				chRedisReturn <- c.String(http.StatusInternalServerError, fmt.Sprintf("Error updating user in Redis: %v", err))
				ch <- false

			}

			c.String(http.StatusOK, "User updated in Redis")
		} else if !existRedis && !existPsql {
			chRedisReturn <- c.String(http.StatusConflict, "Error checking PostgreSQL permissions")
			fmt.Println("User not found")
			return
		}

	}()
	mu.Unlock()
	// If the user does not exist in PostgreSQL or Redis
	return c.String(http.StatusConflict, "Username does not exist in either PostgreSQL or Redis")
}

func user_delete(c echo.Context, psql *sql.DB, rdb *redis.Client) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	if username == "" || password == "" {
		return c.String(http.StatusBadRequest, "Username and password are required")
	}

	// Check if the user exists in Redis
	existRedis, err := rds.CheckLoginRedisExists(rdb, username)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error checking Redis for user existence")
	}

	// Check if the user exists in PostgreSQL
	existPsql, err := postgresdb.CheckLoginPsqlExists(psql, username)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error checking PostgreSQL for user existence")
	}

	// If the user exists in PostgreSQL
	if existPsql {
		// Check user permissions
		userPermission, err := checkPsqlUserPermission(c.Request().Context(), psql, username, password)
		if err != nil {
			return c.String(http.StatusConflict, "Error checking PostgreSQL permissions")
		}
		if userPermission {
			// Retrieve user data
			query := "SELECT salt, password_hash FROM users WHERE username = $1"
			var salt, passwordHash string
			err := psql.QueryRow(query, username).Scan(&salt, &passwordHash)
			if err != nil {
				return c.String(http.StatusInternalServerError, "Error retrieving user data from PostgreSQL")
			}

			// Return user data
			return c.JSON(http.StatusOK, map[string]string{
				"salt":          salt,
				"password_hash": passwordHash,
			})
		}
		return c.String(http.StatusForbidden, "Access denied")
	}

	// If the user exists in Redis
	if existRedis {
		// Check user permissions
		userPermission, err := checkRdsUserPermission(c.Request().Context(), rdb, username, password)
		if err != nil {
			return c.String(http.StatusConflict, "Error checking Redis permissions")
		}
		if userPermission {
			// Retrieve data from Redis
			key := fmt.Sprintf("user:%s", username)
			data, err := rdb.HGetAll(c.Request().Context(), key).Result()
			if err != nil {
				return c.String(http.StatusInternalServerError, "Error retrieving user data from Redis")
			}

			// Ensure all required fields are present
			hash, hashExists := data["hash"]
			salt, saltExists := data["salt"]
			if !hashExists || !saltExists {
				return c.String(http.StatusInternalServerError, "Incomplete user data in Redis")
			}

			// Return user data
			return c.JSON(http.StatusOK, map[string]string{
				"hash": hash,
				"salt": salt,
			})
		}
		return c.String(http.StatusForbidden, "Access denied")
	}

	// If the user is not found
	return c.String(http.StatusNotFound, "User not found")
}

func user_get(c echo.Context, psql *sql.DB, rdb *redis.Client) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	if username == "" || password == "" {
		return c.String(http.StatusBadRequest, "Username and password are required")
	}

	// Check if the user exists in Redis
	existRedis, err := rds.CheckLoginRedisExists(rdb, username)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error checking Redis for user existence")
	}

	// Check if the user exists in PostgreSQL
	existPsql, err := postgresdb.CheckLoginPsqlExists(psql, username)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error checking PostgreSQL for user existence")
	}

	// If the user exists in PostgreSQL
	if existPsql {
		// Check user permissions
		userPermission, err := checkPsqlUserPermission(c.Request().Context(), psql, username, password)
		if err != nil {
			return c.String(http.StatusConflict, "Error checking PostgreSQL permissions")
		}
		if userPermission {
			// Retrieve user data
			query := "SELECT salt, password_hash FROM users WHERE username = $1"
			var salt, passwordHash string
			err := psql.QueryRow(query, username).Scan(&salt, &passwordHash)
			if err != nil {
				return c.String(http.StatusInternalServerError, "Error retrieving user data from PostgreSQL")
			}

			// Return user data
			return c.JSON(http.StatusOK, map[string]string{
				"salt":          salt,
				"password_hash": passwordHash,
			})
		}
		return c.String(http.StatusForbidden, "Access denied")
	}

	// If the user exists in Redis
	if existRedis {
		// Check user permissions
		userPermission, err := checkRdsUserPermission(c.Request().Context(), rdb, username, password)
		if err != nil {
			return c.String(http.StatusConflict, "Error checking Redis permissions")
		}
		if userPermission {
			// Retrieve data from Redis
			key := fmt.Sprintf("user:%s", username)
			data, err := rdb.HGetAll(c.Request().Context(), key).Result()
			if err != nil {
				return c.String(http.StatusInternalServerError, "Error retrieving user data from Redis")
			}

			// Ensure all required fields are present
			hash, hashExists := data["hash"]
			salt, saltExists := data["salt"]
			if !hashExists || !saltExists {
				return c.String(http.StatusInternalServerError, "Incomplete user data in Redis")
			}

			// Return user data
			return c.JSON(http.StatusOK, map[string]string{
				"hash": hash,
				"salt": salt,
			})
		}
		return c.String(http.StatusForbidden, "Access denied")
	}

	// If the user is not found
	return c.String(http.StatusNotFound, "User not found")
}
