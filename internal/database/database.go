package database

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id           int    `json:"id"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
	RefreshToken struct {
		Token      string    `json:"token"`
		Expiration time.Time `json:"expiration"`
	} `json:"refresh_token"`
}

type Chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorId int    `json:"author_id"`
}

type DB struct {
	path string
	mux  *sync.Mutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

func NewDB(path string) (*DB, error) {
	db := &DB{path: path, mux: &sync.Mutex{}}
	if err := db.ensureDB(); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) ensureDB() error {
	if _, err := os.Stat(db.path); err != nil {
		if _, err := os.Create(db.path); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) loadDB() (DBStructure, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	data := DBStructure{Chirps: make(map[int]Chirp), Users: make(map[int]User)}
	dbJSON, err := os.ReadFile(db.path)
	if err != nil {
		return data, err
	}
	if len(dbJSON) > 0 {
		err = json.Unmarshal(dbJSON, &data)
		if err != nil {
			return data, err
		}
	}

	return data, nil
}

func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()
	data, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}
	err = os.WriteFile(db.path, data, 0777)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) CreateChirp(body string, author int) (Chirp, error) {
	data, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	nextId := len(data.Chirps) + 1
	c := Chirp{Id: nextId, Body: body, AuthorId: author}
	data.Chirps[nextId] = c

	err = db.writeDB(data)
	if err != nil {
		return Chirp{}, err
	}
	return c, nil
}

func (db *DB) GetChirps() ([]Chirp, error) {
	data, err := db.loadDB()
	if err != nil {
		return []Chirp{}, err
	}
	chirps := []Chirp{}
	for _, chirp := range data.Chirps {
		chirps = append(chirps, chirp)
	}
	return chirps, nil
}

func (db *DB) GetChirpsByAuthorID(id int) ([]Chirp, error) {
	data, err := db.loadDB()
	if err != nil {
		return []Chirp{}, err
	}

	chirps := []Chirp{}

	for _, chirp := range data.Chirps {
		if chirp.AuthorId == id {
			chirps = append(chirps, chirp)
		}
	}

	return chirps, nil
}

func (db *DB) GetChirp(id int) (Chirp, error) {
	data, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	chirp, ok := data.Chirps[id]
	if !ok {
		return Chirp{}, errors.New("id doesn't exists")
	}
	return chirp, nil
}

func (db *DB) CreateUser(email string, password string) (User, error) {
	data, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	for _, user := range data.Users {
		if user.Email == email {
			return User{}, fmt.Errorf("user with email %s already exists", email)
		}
	}
	nextId := len(data.Users) + 1
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	u := User{Id: nextId, Email: email, Password: string(hashedPassword)}
	data.Users[nextId] = u

	err = db.writeDB(data)
	if err != nil {
		return User{}, err
	}
	return u, nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	data, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range data.Users {
		if user.Email == email {
			return user, nil
		}
	}

	return User{}, errors.New("cannot find user")
}

func (db *DB) GetUserByID(id int) (User, error) {
	data, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, ok := data.Users[id]
	if !ok {
		return User{}, errors.New("cannot find user")
	}

	return user, nil
}

func (db *DB) GetUserByToken(token string) (User, error) {
	data, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	for _, user := range data.Users {
		if user.RefreshToken.Token == token {
			if time.Now().Before(user.RefreshToken.Expiration) {
				return user, nil
			}
			return User{}, errors.New("token expired")
		}
	}
	return User{}, errors.New("updateuser: user doesn't exist with token")
}

func (db *DB) UpdateUser(id int, email string, password string) (User, error) {
	data, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	user, ok := data.Users[id]
	if !ok {
		return User{}, fmt.Errorf("updateuser: user doesn't exist with id %d", id)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}

	user.Email = email
	user.Password = string(hashedPassword)

	data.Users[id] = user

	if err := db.writeDB(data); err != nil {
		return User{}, err
	}
	return data.Users[id], nil
}

func (db *DB) CreateRefreshToken(userId int) (string, error) {
	data, err := db.loadDB()
	if err != nil {
		return "", err
	}
	user, ok := data.Users[userId]
	if !ok {
		return "", errors.New("cannot find user")
	}

	newToken := make([]byte, 32)
	if _, err = rand.Read(newToken); err != nil {
		return "", err
	}

	newTokenString := hex.EncodeToString(newToken)
	user.RefreshToken.Token = newTokenString
	user.RefreshToken.Expiration = time.Now().Add(time.Hour)

	data.Users[user.Id] = user
	err = db.writeDB(data)
	if err != nil {
		return "", err
	}
	return newTokenString, nil
}

func (db *DB) RevokeRefreshToken(token string) error {
	data, err := db.loadDB()
	if err != nil {
		return err
	}
	for _, user := range data.Users {
		if user.RefreshToken.Token == token {
			user.RefreshToken.Token = ""
			user.RefreshToken.Expiration = time.Time{}
			data.Users[user.Id] = user
			if err := db.writeDB(data); err != nil {
				return err
			}
		}
	}
	return nil
}

func (db *DB) DeleteChirp(chirpID int) error {
	data, err := db.loadDB()
	if err != nil {
		return err
	}
	_, ok := data.Chirps[chirpID]
	if !ok {
		return errors.New("chirp doesn't exist")
	}

	delete(data.Chirps, chirpID)

	if err := db.writeDB(data); err != nil {
		return err
	}
	return nil
}

func (db *DB) UpdateUserChirpyRed(userId int, sub bool) error {
	data, err := db.loadDB()
	if err != nil {
		return err
	}
	user, ok := data.Users[userId]
	if !ok {
		return errors.New("user doesn't exist")
	}
	user.IsChirpyRed = sub
	data.Users[user.Id] = user
	if err := db.writeDB(data); err != nil {
		return err
	}
	return nil
}
