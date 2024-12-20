package main

// импорт библиотек
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

// ключ для шифрования
var jwtKey = []byte("your_secret_key")

// структуры с идентификацией в json
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type outData struct {
	ExpArray []int `json:"outExpArray"`
	IncArray []int `json:"outIncArray"`
}
type inData struct {
	ExpArray []int `json:"inpExpArray"`
	IncArray []int `json:"inpIncArray"`
}

// непосредственная генерация jwt токена авторизации
func generateToken(username string) (string, error) {
	claims := &jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// получение имени пользователя из токена
func extractUsernameFromToken(tokenString string) (string, error) {
	// Распарсить токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Проверка использования правильного метода подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		return "", err
	}

	// Проверить claims (полезная информация)
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username, ok := claims["username"].(string)
		if !ok {
			return "", fmt.Errorf("username not found in token")
		}
		return username, nil
	}

	return "", fmt.Errorf("invalid token")
}

// проверка введённых данных (при входе)
func correctCreds(username string, password string) bool {
	fmt.Println("Правильность введённых данных")
	// подключение в базе данных
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	// Отключение от базы данных перед завершением функции
	var exists bool
	// Запрос поиска хотя бы одного пользователя с этим именем и паролем
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
	// подключение в базе данных
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	// Отключение от базы данных перед завершением функции
	var exists bool
	// Запрос поиска хотя бы одного пользователя с этим именем
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

// INSERT или UPDATE функция для записи значений
func updInsFunc(userdatatable string, user_idi int, typo string, amount int) {
	var existingAmount float64
	// подключение в базе данных
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	// Отключение от базы данных перед завершением функции
	switch userdatatable {
	case "userdataexp":
		// начинаем транзакцию
		tx, err := db.Begin()
		if err != nil {
			log.Fatal(err)
		}
		// Сначала проверим, существует ли такой вид дохода для пользователя
		err = tx.QueryRow("SELECT udi.amount FROM userdataexp AS udi WHERE udi.user_id = $1 AND type = $2", user_idi, typo).Scan(&existingAmount)
		if err != nil && err != sql.ErrNoRows {
			log.Fatal(err)
		}

		if err == sql.ErrNoRows {
			// Если нет такого вида дохода, вставляем новый
			_, err = tx.Exec("INSERT INTO userdataexp (user_id, type, amount) VALUES ($1, $2, $3)", user_idi, typo, amount)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			// Если такой доход уже есть, обновляем его
			_, err = tx.Exec("UPDATE userdataexp SET amount = $1 WHERE user_id = $2 AND type = $3", amount, user_idi, typo)
			if err != nil {
				log.Fatal(err)
			}
		}
		// Завершаем транзакцию
		err = tx.Commit()
		if err != nil {
			log.Fatal(err)
		}
	case "userdatainc":
		// начинаем транзакцию
		tx, err := db.Begin()
		if err != nil {
			log.Fatal(err)
		}
		// Сначала проверим, существует ли такой вид дохода для пользователя
		err = tx.QueryRow("SELECT udi.amount FROM userdatainc AS udi WHERE udi.user_id = $1 AND type = $2", user_idi, typo).Scan(&existingAmount)
		if err != nil && err != sql.ErrNoRows {
			log.Fatal(err)
		}

		if err == sql.ErrNoRows {
			// Если нет такого вида дохода, вставляем новый
			_, err = tx.Exec("INSERT INTO userdatainc (user_id, type, amount) VALUES ($1, $2, $3)", user_idi, typo, amount)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			// Если такой доход уже есть, обновляем его
			_, err = tx.Exec("UPDATE userdatainc SET amount = $1 WHERE user_id = $2 AND type = $3", amount, user_idi, typo)
			if err != nil {
				log.Fatal(err)
			}
		}
		// Завершаем транзакцию
		err = tx.Commit()
		if err != nil {
			log.Fatal(err)
		}
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
	// подключение в базе данных
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	// закрытие базы данных перед завершением функции
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
		// добавление куки файла в ответ функции
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",                     // Имя cookie, которое будет использоваться клиентом.
			Value:    token,                            // Значение cookie, в данном случае токен аутентификации.
			Expires:  time.Now().Add(15 * time.Minute), // Дата и время, когда cookie станет недействительной.
			HttpOnly: true,                             // Cookie доступна только серверу.
			Secure:   false,                            // Используйте true, если работаете через HTTPS, чтобы передача cookie была защищенной.
			Path:     "/",                              // Указывает область действия cookie, доступно для всех путей на сервере.
		})

		w.Header().Set("Content-Type", "application/json")
		// отправка данных в сайт через ResponseWriting
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
	// получение конкретного куки файла с токеном аутентификации
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := cookie.Value
	fmt.Print(tokenStr)
	// добавление куки файла в ответ функции
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",                     // Имя cookie, которое будет использоваться клиентом.
		Value:    tokenStr,                         // Значение cookie, в данном случае токен аутентификации.
		Expires:  time.Now().Add(15 * time.Minute), // Дата и время, когда cookie станет недействительной.
		HttpOnly: true,                             // Cookie доступна только серверу.
		Secure:   false,                            // Используйте true, если работаете через HTTPS, чтобы передача cookie была защищенной.
		Path:     "/",                              // Указывает область действия cookie, доступно для всех путей на сервере.
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenStr})
}

// Функция загрузки данных в сайт
func downloadingData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	// создание структуры со слайсами, каждому индексу соответствует определенный вид расходов/доходов
	var outputData = outData{
		ExpArray: make([]int, 8),
		IncArray: make([]int, 5),
	}
	// получение конкретного куки файла с токеном аутентификации
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := cookie.Value
	fmt.Println(tokenStr)
	var username, errorr = extractUsernameFromToken(tokenStr)
	if errorr != nil {
		http.Error(w, "Ошибка обработки токена", http.StatusUnauthorized)
		return
	}
	// подключение в базе данных
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()

	//Поиск данных затрат в базе данных
	rows, err := db.Query("SELECT ude.type, ude.amount FROM public.userdataexp AS ude JOIN public.users AS u ON ude.user_id = u.user_id WHERE u.username = $1", username)
	if err != nil {
		log.Fatalf("Ошибка выполнения SELECT: %v", err)
	}

	for rows.Next() {
		var typ string
		var amount int
		if err := rows.Scan(&typ, &amount); err != nil {
			log.Fatalf("Ошибка чтения строки: %v", err)
		}
		fmt.Println(typ, amount)
		switch typ {
		case "food":
			outputData.ExpArray[0] = amount
			fmt.Println(outputData.ExpArray[0])
		case "entertainment":
			outputData.ExpArray[1] = amount
		case "rent":
			outputData.ExpArray[2] = amount
		case "mortgage":
			outputData.ExpArray[3] = amount
		case "clothes":
			outputData.ExpArray[4] = amount
		case "beauty":
			outputData.ExpArray[5] = amount
		case "investment":
			outputData.ExpArray[6] = amount
		case "otherExp":
			outputData.ExpArray[7] = amount
		default:
			fmt.Println("Не получилось обработать строку: ", typ)
		}
	}
	rows.Close()

	//Поиск данных доходов в базе данных
	rowss, err := db.Query("SELECT udi.type, udi.amount FROM public.userDataInc AS udi JOIN public.users AS u ON udi.user_id = u.user_id WHERE u.username = $1", username)
	if err != nil {
		log.Fatalf("Ошибка выполнения SELECT: %v", err)
	}

	for rowss.Next() {
		var typ string
		var amount int
		if err := rowss.Scan(&typ, &amount); err != nil {
			log.Fatalf("Ошибка чтения строки: %v", err)
		}
		fmt.Println(typ, amount)
		switch typ {
		case "scholarship":
			outputData.IncArray[0] = amount
		case "paycheck":
			outputData.IncArray[1] = amount
		case "dividendts":
			outputData.IncArray[2] = amount
		case "deposit":
			outputData.IncArray[3] = amount
		case "otherInc":
			outputData.IncArray[4] = amount
		default:
			fmt.Println("Не получилось обработать строку: ", typ)
		}
	}
	rowss.Close()
	// добавление куки файла в ответ функции
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",                     // Имя cookie, которое будет использоваться клиентом.
		Value:    tokenStr,                         // Значение cookie, в данном случае токен аутентификации.
		Expires:  time.Now().Add(15 * time.Minute), // Дата и время, когда cookie станет недействительной.
		HttpOnly: true,                             // Cookie доступна только серверу.
		Secure:   false,                            // true, если работа через HTTPS, чтобы передача cookie была защищенной.
		Path:     "/",                              // Указывает область действия cookie, доступно для всех путей на сервере.
	})
	fmt.Println(outputData)
	jsonData, err := json.Marshal(outputData)
	if err != nil {
		log.Fatalf("Ошибка сериализации JSON: %v", err)
	}
	fmt.Println(string(jsonData)) // Выводим JSON перед отправкой
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

// Функция выгрузки данных из сайта
func uploadingData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	var inputData = inData{
		ExpArray: make([]int, 8),
		IncArray: make([]int, 5),
	}
	var user_idi int
	err := json.NewDecoder(r.Body).Decode(&inputData)
	if err != nil {
		http.Error(w, "Ошибка при разборе JSON", http.StatusBadRequest)
		fmt.Println("Ошибка декодирования JSON:", err)
		return
	}
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := cookie.Value
	fmt.Println(tokenStr)
	var username, errorr = extractUsernameFromToken(tokenStr)
	if errorr != nil {
		http.Error(w, "Ошибка обработки токена", http.StatusUnauthorized)
		return
	}
	// подключение к базе данных
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	err = db.QueryRow("SELECT user_id FROM users WHERE username = $1", username).Scan(&user_idi)
	if err != nil {
		log.Fatalf("Ошибка прохождения селекта: %v", err)
	}

	// Вставляем или обновляем доходы
	for i, amount := range inputData.IncArray {
		var userdatatable = "userdatainc"
		var typo string = ""
		switch i {
		case 0:
			typo = "scholarship"
			updInsFunc(userdatatable, user_idi, typo, amount)
		case 1:
			typo = "paycheck"
			updInsFunc(userdatatable, user_idi, typo, amount)
		case 2:
			typo = "dividendts"
			updInsFunc(userdatatable, user_idi, typo, amount)
		case 3:
			typo = "deposit"
			updInsFunc(userdatatable, user_idi, typo, amount)
		case 4:
			typo = "otherInc"
			updInsFunc(userdatatable, user_idi, typo, amount)
		}
		// Вставляем или обновляем расходы
		for i, amount := range inputData.ExpArray {
			var userdatatable = "userdataexp"

			var typo string = ""
			switch i {
			case 0:
				typo = "food"
				updInsFunc(userdatatable, user_idi, typo, amount)
			case 1:
				typo = "entertainment"
				updInsFunc(userdatatable, user_idi, typo, amount)
			case 2:
				typo = "rent"
				updInsFunc(userdatatable, user_idi, typo, amount)
			case 3:
				typo = "mortgage"
				updInsFunc(userdatatable, user_idi, typo, amount)
			case 4:
				typo = "clothes"
				updInsFunc(userdatatable, user_idi, typo, amount)
			case 5:
				typo = "beauty"
				updInsFunc(userdatatable, user_idi, typo, amount)
			case 6:
				typo = "investment"
				updInsFunc(userdatatable, user_idi, typo, amount)
			case 7:
				typo = "otherExp"
				updInsFunc(userdatatable, user_idi, typo, amount)
			}
		}

	}
	// более детальный вывод данных на сайт и вывод в консоль
	fmt.Println(inputData)
	jsonData, err := json.Marshal(inputData)
	if err != nil {
		log.Fatalf("Ошибка сериализации JSON: %v", err)
	}
	fmt.Println(string(jsonData)) // Выводим JSON перед отправкой
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
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
	// подключение к базе данных
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	// закрытие базы данных после всего в функции
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
		// добавление куки файла в ответ функции
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",                     // Имя cookie, которое будет использоваться клиентом.
			Value:    token,                            // Значение cookie, в данном случае токен аутентификации.
			Expires:  time.Now().Add(15 * time.Minute), // Дата и время, когда cookie станет недействительной.
			HttpOnly: true,                             // Cookie доступна только серверу.
			Secure:   false,                            // Используйте true, если работаете через HTTPS, чтобы передача cookie была защищенной.
			Path:     "/",                              // Указывает область действия cookie, доступно для всех путей на сервере.
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}

}

// Основная функция
func main() {
	// создание маршрутов
	r := mux.NewRouter()
	// Подключение к базе данных
	connStr := "user=postgres password=1234 dbname=studydb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()
	// Отключение от базы данных перед завершением функции
	// Проверка соединения
	err = db.Ping()
	if err != nil {
		log.Fatalf("Проверка соединения не удалась: %v", err)
	}

	fmt.Println("Подключение к PostgreSQL успешно!")

	// На всякий случай спрашиваем все логины зарегистрированных пользователей в консоль
	rows, err := db.Query("SELECT username FROM public.users")
	if err != nil {
		log.Fatalf("Ошибка выполнения SELECT: %v", err)
	}
	// закрытие запроса перед окончанием функции
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
	r.HandleFunc("/sign_up", signupFunc)
	r.HandleFunc("/auth", checkAuth)
	r.HandleFunc("/downloadingData", downloadingData)
	r.HandleFunc("/uploadingData", uploadingData)
	// Статическая раздача файлов, запуск файлового сервера
	fs := http.FileServer(http.Dir("./../Frontend/"))
	r.PathPrefix("/").Handler(http.StripPrefix("/", fs))
	r.HandleFunc("/", handleRoot)

	fmt.Println("Server is running on http://localhost:8181")
	log.Fatal(http.ListenAndServe(":8181", r))

}
