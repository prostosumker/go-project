package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

var jwtKey = []byte("your_secret_key")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// непосредственная генерация jwt токена авторизации
func generateToken(username string) (string, error) {
	claims := &jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// проверка введённых данных (при входе)
func correctCreds(username string, password string) bool {
	fmt.Println("Правильность введённых данных")
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	var exists bool
	checkQuery := `SELECT EXISTS (
		SELECT 1 FROM Users WHERE username = $1 AND password = $2
	)`
	err = db.QueryRow(checkQuery, username, password).Scan(&exists)
	if err != nil {
		log.Fatalf("Ошибка при проверке данных: %v", err)
	}
	if exists {
		return true
	} else {
		return false
	}
}

// проверка логина (при регистрации)
func checkLogPass(username string) bool {
	fmt.Println("Проверка логина и пароля")
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	var exists bool
	checkQuery := `SELECT EXISTS (
		SELECT 1 FROM Users WHERE username = $1
	)`
	err = db.QueryRow(checkQuery, username).Scan(&exists)
	if err != nil {
		log.Fatalf("Ошибка при проверке данных: %v", err)
	}
	if exists {
		return true
	} else {
		return false
	}

}

// функция генерации токена при входе в аккаунт
func handleGenerateToken(w http.ResponseWriter, r *http.Request) {
	fmt.Print("dsfgae")
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil || creds.Username == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	var username = creds.Username
	var password = creds.Password
	fmt.Println(username)
	fmt.Println("Пароль", password)
	if correctCreds(creds.Username, creds.Password) {
		token, err := generateToken(creds.Username)
		if err != nil {
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			Expires:  time.Now().Add(5 * time.Minute),
			HttpOnly: true,
			Secure:   false, // Используйте true, если работаете с HTTPS
			Path:     "/",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	} else {
		fmt.Println("Нерпавильные данные")
		http.Error(w, "Имя или пароль неправильные.", http.StatusInternalServerError)
	}

}

// перенаправление на страницу авторизации
func handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/signInPage.html", http.StatusFound)
}

// проверка jwt токена авторизации
func checkAuth(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := cookie.Value
	fmt.Print(tokenStr)
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    tokenStr,
		Expires:  time.Now().Add(10 * time.Second),
		HttpOnly: true,
		Secure:   false, // Используйте true, если работаете с HTTPS
		Path:     "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenStr})
}

// Функция загрузки данных в сайт
func downloadingData(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := cookie.Value
	fmt.Println(tokenStr)

}

// Функция выгрузки данных из сайта
func uploadingData(w http.ResponseWriter, r *http.Request) {

}

// Функция работы с авторизованным пользователем (в разработке)
func authorizedFunc(w http.ResponseWriter, r *http.Request) {

}

// Функция регистрации пользователя
func signupFunc(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil || creds.Username == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	var username = creds.Username
	var password = creds.Password
	fmt.Println(username)
	fmt.Println("Пароль", password)
	if checkLogPass(creds.Username) {
		fmt.Println("Имя уже существует")
		http.Error(w, "Пользователь с таким именем уже существует.", http.StatusInternalServerError)
	} else {
		fmt.Println("Пытаемся вставить новый акк")
		// Если пользователя нет, вставляем данные
		insertQuery := `INSERT INTO Users (username, password) VALUES ($1, $2) RETURNING user_id`
		var userID int
		err = db.QueryRow(insertQuery, username, password).Scan(&userID)
		if err != nil {
			log.Fatalf("Ошибка при вставке данных: %v", err)
		}
		fmt.Printf("Новый пользователь добавлен с ID: %d\n", userID)
		token, err := generateToken(creds.Username)
		if err != nil {
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			Expires:  time.Now().Add(5 * time.Minute),
			HttpOnly: true,
			Secure:   false, // Используйте true, если работаете с HTTPS
			Path:     "/",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}

}

// Основная функция
func main() {
	r := mux.NewRouter()
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()

	// Проверка соединения
	err = db.Ping()
	if err != nil {
		log.Fatalf("Проверка соединения не удалась: %v", err)
	}

	fmt.Println("Подключение к PostgreSQL успешно!")

	// На всякий случай спрашиваем все логины зарегистрированных пользователей
	rows, err := db.Query("SELECT username FROM public.users")
	if err != nil {
		log.Fatalf("Ошибка выполнения SELECT: %v", err)
	}
	defer rows.Close()
	fmt.Println("Список имён:")
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Fatalf("Ошибка чтения строки: %v", err)
		}
		fmt.Println(name)
	}
	//различные функции, вызываемые с помощью javascript
	r.HandleFunc("/generate-token", handleGenerateToken)
	r.HandleFunc("/welcome.html", authorizedFunc)
	r.HandleFunc("/sign_up", signupFunc)
	r.HandleFunc("/auth", checkAuth)
	// Статическая раздача файлов
	fs := http.FileServer(http.Dir("./../Frontend/"))
	r.PathPrefix("/").Handler(http.StripPrefix("/", fs))
	r.HandleFunc("/", handleRoot)

	fmt.Println("Server is running on http://localhost:8181")
	log.Fatal(http.ListenAndServe(":8181", r))

}
