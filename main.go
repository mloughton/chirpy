package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"

	"github.com/mloughton/chirpy/internal/database"
	"golang.org/x/crypto/bcrypt"
)

type apiConfig struct {
	db             *database.DB
	jwtSecret      string
	polkaAPIKey    string
	fileserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) HandleGetMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits)))
}

func (cfg *apiConfig) HandleResetMetrics(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.WriteHeader(http.StatusOK)
}

func appHandler() http.Handler {
	return http.StripPrefix("/app", http.FileServer(http.Dir(".")))
}

func (cfg *apiConfig) HandleGetAdminMetrics(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./admin/metrics/index.html")
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	err = tmpl.Execute(w, cfg.fileserverHits)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println(err)
		return
	}
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type response struct {
		Error string `json:"error"`
	}
	responseBody := response{
		Error: msg,
	}
	respondWithJSON(w, code, responseBody)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	responseJSON, err := json.Marshal(payload)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(responseJSON)
}

func Clean(s string) string {
	badWords := []string{"kerfuffle", "sharbert", "fornax"}
	words := strings.Split(s, " ")
	for i, word := range words {
		if slices.Contains[[]string](badWords, strings.ToLower(word)) {
			words[i] = "****"
		}
	}
	return strings.Join(words, " ")
}

func (cfg *apiConfig) HandlePostChirps(w http.ResponseWriter, r *http.Request) {
	token := cfg.GetToken(r)
	if token == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	type request struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	req := request{}
	err := decoder.Decode(&req)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if len(req.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}

	idString, err := token.Claims.GetSubject()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	id, err := strconv.Atoi(idString)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res, err := cfg.db.CreateChirp(Clean(req.Body), id)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusCreated, res)
}

func (cfg *apiConfig) HandleGetChirps(w http.ResponseWriter, r *http.Request) {
	chirps, err := cfg.db.GetChirps()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sort.Slice(chirps, func(i, j int) bool {
		return chirps[i].Id < chirps[j].Id
	})
	respondWithJSON(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) HandleGetChirp(w http.ResponseWriter, r *http.Request) {
	chirpId, err := strconv.Atoi(r.PathValue("chirpId"))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	chirp, err := cfg.db.GetChirp(chirpId)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	respondWithJSON(w, http.StatusOK, chirp)
}

func (cfg *apiConfig) HandlePostUsers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.CreateUser(req.Email, req.Password)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := struct {
		Id          int    `json:"id"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}{
		Id:          user.Id,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}

	respondWithJSON(w, http.StatusCreated, res)
}

func (cfg *apiConfig) HandlePostLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.GetUserByEmail(req.Email)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	signedJWTToken, err := cfg.GenerateJWTToken(user)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshToken, err := cfg.db.CreateRefreshToken(user.Id)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := struct {
		Id           int    `json:"id"`
		Email        string `json:"email"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}{
		Id:           user.Id,
		Email:        user.Email,
		IsChirpyRed:  user.IsChirpyRed,
		Token:        signedJWTToken,
		RefreshToken: refreshToken,
	}

	respondWithJSON(w, http.StatusOK, res)

}

func (cfg *apiConfig) HandlePutUsers(w http.ResponseWriter, r *http.Request) {
	token := cfg.GetToken(r)

	if token == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	idString, err := token.Claims.GetSubject()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	id, err := strconv.Atoi(idString)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := cfg.db.UpdateUser(id, req.Email, req.Password)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := struct {
		Id          int    `json:"id"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}{
		Id:          user.Id,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}
	respondWithJSON(w, http.StatusOK, res)
}

func (cfg *apiConfig) GenerateJWTToken(user database.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 3600)),
		Subject:   fmt.Sprint(user.Id),
	})

	signedToken, err := token.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		return "", err
	}

	return signedToken, err
}

func (cfg *apiConfig) HandlePostRefresh(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:]
	user, err := cfg.db.GetUserByToken(tokenString)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	newToken, err := cfg.GenerateJWTToken(user)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	res := struct {
		Token string `json:"token"`
	}{
		Token: newToken,
	}
	respondWithJSON(w, http.StatusOK, res)
}

func (cfg *apiConfig) HandlePostRevoke(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:]
	if err := cfg.db.RevokeRefreshToken(tokenString); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) GetToken(r *http.Request) *jwt.Token {
	tokenString := r.Header.Get("Authorization")[7:]
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.jwtSecret), nil
	})

	if err != nil {
		return nil
	}
	return token
}

func (cfg *apiConfig) HandleDeleteChirp(w http.ResponseWriter, r *http.Request) {
	token := cfg.GetToken(r)
	if token == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	chirpId, err := strconv.Atoi(r.PathValue("chirpId"))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	chirp, err := cfg.db.GetChirp(chirpId)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	idString, err := token.Claims.GetSubject()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userID, err := strconv.Atoi(idString)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if chirp.AuthorId != userID {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if err := cfg.db.DeleteChirp(chirpId); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) HandlePostPolkaWebhook(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.Contains(authHeader, "ApiKey ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if authHeader[7:] != cfg.polkaAPIKey {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req struct {
		Event string `json:"event"`
		Data  struct {
			UserId int `json:"user_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if req.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	user, err := cfg.db.GetUserByID(req.Data.UserId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !user.IsChirpyRed {
		if err := cfg.db.UpdateUserChirpyRed(req.Data.UserId, true); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {

	godotenv.Load()

	dbg := flag.Bool("debug", false, "Enable debug mode")
	flag.Parse()

	if *dbg {
		os.Remove("./database.json")
	}

	db, err := database.NewDB("./database.json")
	if err != nil {
		log.Println(err)
		return
	}

	apiCfg := &apiConfig{
		db:          db,
		jwtSecret:   os.Getenv("JWT_SECRET"),
		polkaAPIKey: os.Getenv("POLKA_API_KEY"),
	}

	mux := http.NewServeMux()
	mux.Handle("/app/*", apiCfg.middlewareMetricsInc(appHandler()))

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("GET /api/metrics", apiCfg.HandleGetMetrics)

	mux.HandleFunc("/api/reset", apiCfg.HandleResetMetrics)

	mux.HandleFunc("POST /api/chirps", apiCfg.HandlePostChirps)

	mux.HandleFunc("GET /api/chirps", apiCfg.HandleGetChirps)

	mux.HandleFunc("GET /api/chirps/{chirpId}", apiCfg.HandleGetChirp)

	mux.HandleFunc("DELETE /api/chirps/{chirpId}", apiCfg.HandleDeleteChirp)

	mux.HandleFunc("POST /api/users", apiCfg.HandlePostUsers)

	mux.HandleFunc("POST /api/login", apiCfg.HandlePostLogin)

	mux.HandleFunc("PUT /api/users", apiCfg.HandlePutUsers)

	mux.HandleFunc("POST /api/refresh", apiCfg.HandlePostRefresh)

	mux.HandleFunc("POST /api/revoke", apiCfg.HandlePostRevoke)

	mux.HandleFunc("GET /admin/metrics/", apiCfg.HandleGetAdminMetrics)

	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.HandlePostPolkaWebhook)

	server := &http.Server{
		Handler: mux,
		Addr:    "localhost:8080",
	}

	log.Printf("listening and serving on %s : open using http://localhost:8080/app", server.Addr)
	server.ListenAndServe()
}
