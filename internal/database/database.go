package database

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type User struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
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

func (db *DB) CreateChirp(body string) (Chirp, error) {
	data, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	nextId := len(data.Chirps) + 1
	c := Chirp{Id: nextId, Body: body}
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

func (db *DB) CreateUser(email string) (User, error) {
	data, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	nextId := len(data.Users) + 1
	u := User{Id: nextId, Email: email}
	data.Users[nextId] = u

	err = db.writeDB(data)
	if err != nil {
		return User{}, err
	}
	return u, nil
}
