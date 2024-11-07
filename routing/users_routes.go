package router

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	postgresdb "hello/postgresdb"
	rds "hello/redis"
	"net/http"

	//"github.com/gorilla/sessions"
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

func checkPsqlUserPermission(db *sql.DB, username string, password string) (bool, error) {
	// Запрос для получения соли и хэша пароля из базы данных
	var salt string
	var passwordHash string

	query := "SELECT salt, password_hash FROM users WHERE username = $1"
	err := db.QueryRow(query, username).Scan(&salt, &passwordHash)

	// Проверяем, существует ли пользователь
	if err == sql.ErrNoRows {
		return false, fmt.Errorf("User not found")
	} else if err != nil {
		return false, fmt.Errorf("Error retrieving user data from PostgreSQL: %v", err)
	}

	// Проверка хэша пароля
	saltBytes := []byte(salt)
	hashedPassword := hashPassword(password, saltBytes)
	if bytes.Equal(hashedPassword, []byte(passwordHash)) {
		return true, nil
	} else {
		return false, fmt.Errorf("Password not correct")
	}
}

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
	new_password := c.FormValue("new_password")

	// Check if the user exists in Redis
	existRedis, err := rds.CheckLoginRedisExists(rdb, username)
	if err != nil {
		return err
	}

	// Check if the user exists in PostgreSQL
	existPsql, err := postgresdb.CheckLoginPsqlExists(psql, username)
	if err != nil {
		return err
	}

	if existRedis {
		// Check user permissions in Redis
		user_permission, err := checkRdsUserPermission(ctx, rdb, username, password)
		if err != nil {
			return c.String(http.StatusConflict, "Error checking Redis permissions")
		}

		if !user_permission {
			return c.String(http.StatusConflict, "No permission")
		}

		// If the user has permissions, proceed
		//go timer(psql, rdb)
		userKey := fmt.Sprintf("user:%s", username)

		// Retrieve user data from Redis
		user, err := rds.GetRedisData(rdb, userKey)
		if err != nil {
			return fmt.Errorf("Error getting user data from Redis: %v", err)
		}

		// Hash the new password
		hashedPassword := hashPassword(new_password, []byte(user["salt"]))

		// Update user data in Redis
		if err := rdb.HSet(ctx, userKey, map[string]interface{}{
			"password_hash": string(hashedPassword),
			"salt":          user["salt"],
		}).Err(); err != nil {
			return fmt.Errorf("Error updating user in Redis: %v", err)
		}

		// Lock access to user counter and check the limit
		mu.Lock()
		defer mu.Unlock()

		userCount, err := rds.CheckUserCount(rdb)
		if err != nil {
			return fmt.Errorf("Error checking user count: %v", err)
		}

		if userCount >= int(GetParams("MAX_USER_COUNT_BUFFER")) {
			// If user limit is reached, perform batch insert
			if err := batchInsertUsers(psql, rdb); err != nil {
				return fmt.Errorf("Error during batch insert: %v", err)
			}

			sended = true
			sended_ch <- true
			fmt.Println("Batch insert complete")
		}
		if existPsql {
			// Check user permissions in PostgreSQL
			user_permission, err := checkPsqlUserPermission(psql, username, password)
			if err != nil {
				return c.String(http.StatusConflict, "Error checking PostgreSQL permissions")
			}

			if !user_permission {
				return c.String(http.StatusConflict, "No permission")
			}

			// Retrieve the salt from Redis if available, or define alternative behavior
			userKey := fmt.Sprintf("user:%s", username)
			user, err := rds.GetRedisData(rdb, userKey)
			if err != nil {
				return fmt.Errorf("Error getting user data from Redis: %v", err)
			}

			// Hash the new password
			hashedPassword := hashPassword(new_password, []byte(user["salt"]))

			// SQL query for updating the row
			query := "UPDATE users SET password_hash = $1, salt = $2 WHERE username = $3"
			result, err := psql.Exec(query, hashedPassword, user["salt"], username)
			if err != nil {
				return fmt.Errorf("Error updating user in PostgreSQL: %v", err)
			}

			// Check the number of rows affected
			rowsAffected, err := result.RowsAffected()
			if err != nil {
				return fmt.Errorf("Error checking affected rows: %v", err)
			}

			if rowsAffected == 0 {
				return c.String(http.StatusConflict, "No rows were updated, username may not exist")
			}

			fmt.Println("User updated successfully in PostgreSQL")
			return c.String(http.StatusOK, "User updated in PostgreSQL")
		}

		// Return response indicating successful user update in Redis
		return c.String(http.StatusOK, "User updated in Redis")

	} else if existPsql {
		// Check user permissions in PostgreSQL
		user_permission, err := checkPsqlUserPermission(psql, username, password)
		if err != nil {
			return c.String(http.StatusConflict, "Error checking PostgreSQL permissions")
		}

		if !user_permission {
			return c.String(http.StatusConflict, "No permission")
		}

		// Retrieve the salt from Redis if available, or define alternative behavior
		userKey := fmt.Sprintf("user:%s", username)
		user, err := rds.GetRedisData(rdb, userKey)
		if err != nil {
			return fmt.Errorf("Error getting user data from Redis: %v", err)
		}

		// Hash the new password
		hashedPassword := hashPassword(new_password, []byte(user["salt"]))

		// SQL query for updating the row
		query := "UPDATE users SET password_hash = $1, salt = $2 WHERE username = $3"
		result, err := psql.Exec(query, hashedPassword, user["salt"], username)
		if err != nil {
			return fmt.Errorf("Error updating user in PostgreSQL: %v", err)
		}

		// Check the number of rows affected
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("Error checking affected rows: %v", err)
		}

		if rowsAffected == 0 {
			return c.String(http.StatusConflict, "No rows were updated, username may not exist")
		}

		fmt.Println("User updated successfully in PostgreSQL")
		return c.String(http.StatusOK, "User updated in PostgreSQL")
	}

	return c.String(http.StatusConflict, "Username does not exist")
}

func users_list(c echo.Context, psql *sql.DB, rdb *redis.Client) error {

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
	if existRedis || existPsql {

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

	//return c.String(http.StatusUnauthorized, "Invalid credentials")
}

func user_delete(c echo.Context, psql *sql.DB, rdb *redis.Client) error {

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
	if existRedis || existPsql {

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
}
