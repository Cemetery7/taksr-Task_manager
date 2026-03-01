package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// создание структур

type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"` // никогда не отправляем клиенту
}

type Task struct {
	ID        int       `json:"id"`
	UserID    int       `json:"-"`
	Title     string    `json:"title"`
	Done      bool      `json:"done"`
	CreatedAt time.Time `json:"created_at"`
}

// ── Хранилище в памяти ────────

type Store struct {
	mu      sync.RWMutex
	users   []User
	tasks   []Task
	userSeq int
	taskSeq int
	// токен → userID
	sessions map[string]int
}

var store = &Store{
	sessions: make(map[string]int),
}

func (s *Store) CreateUser(username, password string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.Username == username {
			return nil, fmt.Errorf("пользователь уже существует")
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	s.userSeq++
	user := User{
		ID:           s.userSeq,
		Username:     username,
		PasswordHash: string(hash),
	}
	s.users = append(s.users, user)
	return &user, nil
}

func (s *Store) AuthUser(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.users {
		if u.Username == username {
			err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
			if err != nil {
				return nil, fmt.Errorf("неверный пароль")
			}
			return &u, nil
		}
	}
	return nil, fmt.Errorf("пользователь не найден")
}

func (s *Store) CreateSession(userID int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	// токен: "uid-<id>-<timestamp>"
	token := fmt.Sprintf("uid-%d-%d", userID, time.Now().UnixNano())
	s.sessions[token] = userID
	return token
}

func (s *Store) GetUserIDByToken(token string) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.sessions[token]
	return id, ok
}

func (s *Store) DeleteSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *Store) GetTasks(userID int) []Task {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Task
	for _, t := range s.tasks {
		if t.UserID == userID {
			result = append(result, t)
		}
	}
	if result == nil {
		result = []Task{} // чтобы фронт получил [] а не null
	}
	return result
}

func (s *Store) CreateTask(userID int, title string) Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.taskSeq++
	task := Task{
		ID:        s.taskSeq,
		UserID:    userID,
		Title:     title,
		Done:      false,
		CreatedAt: time.Now(),
	}
	s.tasks = append(s.tasks, task)
	return task
}

func (s *Store) UpdateTask(taskID, userID int, done bool) (*Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.tasks {
		if t.ID == taskID {
			if t.UserID != userID {
				return nil, fmt.Errorf("нет доступа")
			}
			s.tasks[i].Done = done
			updated := s.tasks[i]
			return &updated, nil
		}
	}
	return nil, fmt.Errorf("задача не найдена")
}

func (s *Store) DeleteTask(taskID, userID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.tasks {
		if t.ID == taskID {
			if t.UserID != userID {
				return fmt.Errorf("нет доступа")
			}
			s.tasks = append(s.tasks[:i], s.tasks[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("задача не найдена")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		panic(err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func extractToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "токен не передан")
			return
		}
		userID, ok := store.GetUserIDByToken(token)
		if !ok {
			writeError(w, http.StatusUnauthorized, "недействительный токен")
			return
		}
		r.Header.Set("X-User-ID", strconv.Itoa(userID))
		next(w, r)
	}
}

func getUserID(r *http.Request) int {
	id, _ := strconv.Atoi(r.Header.Get("X-User-ID"))
	return id
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "невалидный JSON")
		return
	}
	if body.Username == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "нужно указать username и password")
		return
	}
	if len(body.Password) < 4 {
		writeError(w, http.StatusBadRequest, "пароль должен быть минимум 4 символа")
		return
	}

	user, err := store.CreateUser(body.Username, body.Password)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	token := store.CreateSession(user.ID)
	writeJSON(w, http.StatusCreated, map[string]string{"token": token})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "невалидный JSON")
		return
	}

	user, err := store.AuthUser(body.Username, body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	token := store.CreateSession(user.ID)
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func handleTasks(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)

	switch r.Method {
	case http.MethodGet:
		tasks := store.GetTasks(userID)
		writeJSON(w, http.StatusOK, tasks)

	case http.MethodPost:
		var body struct {
			Title string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "невалидный JSON")
			return
		}
		if strings.TrimSpace(body.Title) == "" {
			writeError(w, http.StatusBadRequest, "title не может быть пустым")
			return
		}

		task := store.CreateTask(userID, strings.TrimSpace(body.Title))
		writeJSON(w, http.StatusCreated, task)

	default:
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

func handleTask(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)

	parts := strings.Split(r.URL.Path, "/")
	taskID, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		writeError(w, http.StatusBadRequest, "невалидный id задачи")
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var body struct {
			Done bool `json:"done"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "невалидный JSON")
			return
		}

		task, err := store.UpdateTask(taskID, userID, body.Done)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, task)

	case http.MethodDelete:
		if err := store.DeleteTask(taskID, userID); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		writeError(w, http.StatusMethodNotAllowed, "метод не поддерживается")
	}
}

func setupRoutes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/register", handleRegister)
	mux.HandleFunc("/api/login", handleLogin)

	mux.HandleFunc("/api/tasks", authMiddleware(handleTasks))
	mux.HandleFunc("/api/tasks/", authMiddleware(handleTask))

	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/", fs)

	return corsMiddleware(mux)
}

func main() {
	router := setupRoutes()

	addr := ":8081"
	log.Printf("🚀 Сервер запущен на http://localhost%s", addr)
	log.Printf("📁 Открой http://localhost%s в браузере", addr)

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatal(err)
	}
}
