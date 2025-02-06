package postgresdb

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var (
	host     string
	port     string
	user     string
	password string
	dbname   string
)

func init() {

	err := godotenv.Load()
	if err != nil {
		return
	}

	host = os.Getenv("PSQL_HOST")
	port = os.Getenv("PSQL_PORT")
	user = os.Getenv("PSQL_USER")
	password = os.Getenv("PSQL_PASSWORD")
	dbname = os.Getenv("PSQL_DBNAME")

	requiredEnvVars := []string{"PSQL_HOST", "PSQL_PORT", "PSQL_USER", "PSQL_PASSWORD", "PSQL_DBNAME"}
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			panic(fmt.Sprintf("Environment variable %s is required but not set", envVar))
		}
	}
}

func getDBConnectionString() string {
	port, err := strconv.Atoi(os.Getenv("PSQL_PORT"))
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

func GetPsqlData(db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT salt, password_hash  FROM users WHERE key = $1", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no value found for key: %s", key)
	} else if err != nil {
		return "", err
	}
	return value, nil
}
