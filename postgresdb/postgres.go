package postgresdb

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"

	_ "github.com/lib/pq"
)

var (
	host     = os.Getenv("HOST")
	port     = os.Getenv("PORT")
	user     = os.Getenv("USER")
	password = os.Getenv("PASSWORD")
	dbname   = os.Getenv("DBNAME")
)

func init() {
	requiredEnvVars := []string{"HOST", "PORT", "USER", "PASSWORD", "DBNAME"}
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			panic(fmt.Sprintf("Environment variable %s is required but not set", envVar))
		}
	}
}

func getDBConnectionString() string {
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		panic("Invalid PORT environment variable")
	}
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
}

func CheckLoginPsqlExists(db *sql.DB, login string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)`
	err := db.QueryRow(query, login).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func ConnectDB() (*sql.DB, error) {
	psqlconn := getDBConnectionString()
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	return db, nil
}

func set(db *sql.DB, key string, value string) error {
	_, err := db.Exec("INSERT INTO key_value_store (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", key, value)
	return err
}

func get(db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM key_value_store WHERE key = $1", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no value found for key: %s", key)
	} else if err != nil {
		return "", err
	}
	return value, nil
}
