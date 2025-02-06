package redis

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-redis/redis/v8"
)

var (
	host     = os.Getenv("RDS_HOST")
	port     = os.Getenv("RDS_PORT")
	password = os.Getenv("RDS_PASSWORD")
	dbname   = os.Getenv("RDS_DBNAME")
)

var ctx = context.Background()

func GetParams(param string) int {
	defaultCount := map[string]int{
		"MAX_USER_COUNT_BUFFER": 100, // Minimum amount of memory in MB (64 MB is the lowest usable value)
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

	// If the key is not found, return 0 or any other default value.
	return 0
}

func parseRedisKey(key string) []string {
	parts := strings.Split(key, ":")
	return parts
}

func ParseIdRedis(key string) (string, error) {
	parts := parseRedisKey(key)
	if 2 < len(parts) {
		return "", errors.New("The Redis key ID was not found. Please check the key.")
	}
	return parts[1], nil
}

// ConnectRedis establishes a connection to Redis
func ConnectRedis() (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", host, port),
		Password: password,
		DB:       0, // Use 0 for the default database
	})

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Error connecting to Redis: %v", err)
		return nil, err
	}

	fmt.Println("Connection to Redis established successfully")
	return rdb, nil
}

// AddUser adds a user to the list
func AddUser(rdb *redis.Client, username string, salt []byte, hashedPassword []byte) error {
	err := rdb.HSet(ctx, fmt.Sprintf("user:%s", username), map[string]interface{}{
		"password_hash": hashedPassword,
		"salt":          salt,
	}).Err()
	if err != nil {
		return fmt.Errorf("Error adding user to Redis: %v", err)
	}

	fmt.Printf("User %s successfully added\n", username)
	return nil
}

func validatePrefix(prefix string) (string, error) {

	re := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{2,19}$`)

	if !re.MatchString(prefix) {
		return "", errors.New("Prefix does not meet the required rules")
	}
	return prefix, nil
}

func CheckLoginRedisExists(rdb *redis.Client, login string) (bool, error) {
	userKey := fmt.Sprintf("user:%s", login)

	exists, err := rdb.Exists(ctx, userKey).Result()
	if err != nil {
		return false, fmt.Errorf("Error checking user existence in Redis: %v", err)
	}
	if exists == 1 {
		fmt.Println(exists)
		return true, nil
	} else if exists == 0 {
		return false, nil
	} else {
		fmt.Println(err)
		fmt.Println(exists)
		fmt.Println("else")
		return false, fmt.Errorf("Error checking user existence in Redis: %v", err)
	}
}

func GetUserKeys(rdb *redis.Client, prefix string) ([]string, error) {
	var keys []string
	var cursor uint64
	prefix, err := validatePrefix(prefix)
	if err != nil {
		return nil, err
	}
	fmt.Println("Here Ok")
	for {
		scannedKeys, newCursor, err := rdb.Scan(ctx, cursor, prefix+":*", 0).Result()
		if err != nil {
			return nil, fmt.Errorf("Getting keys error: %v", err)
		}
		fmt.Println(scannedKeys)
		fmt.Println(newCursor)
		keys = append(keys, scannedKeys...)
		if newCursor == 0 {
			break
		}
		cursor = newCursor
	}
	fmt.Println(keys)
	fmt.Println(cursor)
	return keys, nil
}

func CheckUserCount(rdb *redis.Client) (int, error) {
	var cursor uint64
	var count int
	for {
		keys, nextCursor, err := rdb.Scan(ctx, cursor, "user:*", int64(GetParams("MAX_USER_COUNT_BUFFER"))).Result()
		if err != nil {
			return 0, fmt.Errorf("Error scanning keys in Redis: %v", err)
		}
		count += len(keys)
		cursor = nextCursor
		if cursor == 0 { // Завершение, если больше ключей нет
			break
		}
	}
	return count, nil
}

// Вопрос безопасности? Если злоумышленик получит доступ к этой функции, то сможет тоскать все данные из системы
func GetRedisData(rdb *redis.Client, key string) (map[string]string, error) {
	userData, err := rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	return userData, nil
}
