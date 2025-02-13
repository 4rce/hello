package postgresdb

/*import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"

	_ "github.com/lib/pq"
)

// Структура для представления модели в базе данных
type OnnxModel struct {
	ID        int
	Name      string
	ModelData []byte
	CreatedAt string
}

// Открытие соединения с PostgreSQL
func openDB() (*sql.DB, error) {
	connStr := "user=yourusername password=yourpassword dbname=yourdbname sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Создание новой модели
func createModel(db *sql.DB, name string, modelPath string) error {
	// Считываем модель из файла
	modelData, err := readFile(modelPath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать файл модели: %v", err)
	}

	// Вставка в базу данных
	_, err = db.Exec("INSERT INTO onnx_models(name, model_data) VALUES($1, $2)", name, modelData)
	if err != nil {
		return fmt.Errorf("не удалось вставить модель в базу данных: %v", err)
	}

	return nil
}

// Функция для считывания файла
func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть файл: %v", err)
	}
	defer file.Close()

	return io.ReadAll(file)
}

// Получение модели по имени
func getModel(db *sql.DB, name string) (*OnnxModel, error) {
	var model OnnxModel
	err := db.QueryRow("SELECT id, name, model_data, created_at FROM onnx_models WHERE name = $1", name).
		Scan(&model.ID, &model.Name, &model.ModelData, &model.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("модель с именем '%s' не найдена", name)
		}
		return nil, fmt.Errorf("ошибка при получении модели: %v", err)
	}
	return &model, nil
}

// Обновление модели
func updateModel(db *sql.DB, id int, modelPath string) error {
	// Считываем модель из файла
	modelData, err := readFile(modelPath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать файл модели: %v", err)
	}

	// Обновление модели в базе данных
	_, err = db.Exec("UPDATE onnx_models SET model_data = $1 WHERE id = $2", modelData, id)
	if err != nil {
		return fmt.Errorf("не удалось обновить модель: %v", err)
	}

	return nil
}

// Удаление модели
func deleteModel(db *sql.DB, id int) error {
	// Удаление модели из базы данных
	_, err := db.Exec("DELETE FROM onnx_models WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("не удалось удалить модель: %v", err)
	}

	return nil
}

// Основная функция
func main() {
	// Подключение к базе данных
	db, err := openDB()
	if err != nil {
		log.Fatalf("Ошибка при подключении к базе данных: %v", err)
	}
	defer db.Close()

	// Создание модели
	err = createModel(db, "example_model", "path_to_your_model.onnx")
	if err != nil {
		log.Fatalf("Ошибка при создании модели: %v", err)
	}
	fmt.Println("Модель успешно добавлена в базу данных")

	// Получение модели
	model, err := getModel(db, "example_model")
	if err != nil {
		log.Fatalf("Ошибка при получении модели: %v", err)
	}
	fmt.Printf("Модель '%s' успешно получена, размер данных: %d байт\n", model.Name, len(model.ModelData))

	// Обновление модели
	err = updateModel(db, model.ID, "path_to_new_model.onnx")
	if err != nil {
		log.Fatalf("Ошибка при обновлении модели: %v", err)
	}
	fmt.Println("Модель успешно обновлена")

	// Удаление модели
	err = deleteModel(db, model.ID)
	if err != nil {
		log.Fatalf("Ошибка при удалении модели: %v", err)
	}
	fmt.Println("Модель успешно удалена")
}
*/
