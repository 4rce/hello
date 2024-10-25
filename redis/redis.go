package redis

import (
	"context"
	"errors"
	"strings"

	//"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"

	//"sync"
	//"time"

	"github.com/go-redis/redis/v8"
)

var (
	host     = os.Getenv("RDS_HOST")
	port     = os.Getenv("RDS_PORT")
	password = os.Getenv("RDS_PASSWORD")
	dbname   = os.Getenv("RDS_DBNAME")
)

var ctx = context.Background()

var registrations []User // Array for storing users
const maxRegistrations = 100

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
}

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

	// Если ключ не найден, возвращаем 0 или любое другое значение по умолчанию
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

/*
// StartTimer starts a timer for 1 hour

	func StartTimer(rdb *redis.Client) {
		go func() {
			for {
				time.Sleep(5 * time.Second)

				userLock.Lock()
				if len(registrations) > 0 {
					// Send remaining users if less than 100
					sendToDatabase(registrations)
					registrations = nil // Clear the list
				}
				userLock.Unlock()
			}
		}()
	}
*/
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
		fmt.Println(err)
		fmt.Println("err!=nil")
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
	for {
		scannedKeys, newCursor, err := rdb.Scan(ctx, cursor, prefix+":*", 0).Result()
		if err != nil {
			return nil, fmt.Errorf("Getting keys error: %v", err)
		}
		keys = append(keys, scannedKeys...)
		if newCursor == 0 {
			break
		}
		cursor = newCursor
	}

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

/*func GetUsersFromRedis(rdb *redis.Client) ([]User, error) {
	var users []User
	var cursor uint64

	// Use SCAN to iterate over the keys
	for {
		// Get the next set of keys
		keys, nextCursor, err := rdb.Scan(ctx, cursor, "user:*", 0).Result()
		if err != nil {
			return nil, fmt.Errorf("error scanning keys: %v", err)
		}

		// Iterate over the retrieved keys
		for _, key := range keys {
			// Get the value associated with the key
			val, err := rdb.HGetAll(ctx, key).Result() // Assuming user data is stored in a hash
			if err != nil {
				return nil, fmt.Errorf("error retrieving user data for key %s: %v", key, err)
			}

			// Create a User struct and append it to the users slice
			user := User{
				Username: val["username"], // Assuming username is stored under this field
				Email:    val["email"],    // Assuming email is stored under this field
			}
			users = append(users, user)
		}

		// If the cursor is 0, we have iterated through all keys
		if nextCursor == 0 {
			break
		}
		cursor = nextCursor
	}

	return users, nil
}*/

/*func LoadFromDisk() ([]User, error) {
	file, err := os.Open("backup.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []User
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func SaveToDisk(users []User) {
	file, err := os.Create("backup.json")
	if err != nil {
		log.Fatalf("Error creating file: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(users)
	if err != nil {
		log.Fatalf("Error saving data: %v", err)
	}
}

*/

func AddSession(rdb *redis.Client, sessionID string, cookie string) error {
	err := rdb.Set(ctx, sessionID, cookie, 0).Err()
	if err != nil {
		return fmt.Errorf("Error setting session: %v", err)
	}
	return nil
}

func CheckSession(rdb *redis.Client, sessionID string) (string, error) {
	cookie, err := rdb.Get(ctx, sessionID).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("Session not found: %s", sessionID)
	} else if err != nil {
		return "", fmt.Errorf("Error retrieving session: %v", err)
	}
	return cookie, nil
}
