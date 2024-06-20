package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mloughton/chirpy/internal/database"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) RegisterRoutes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/app/*", s.middlewareMetricsInc(s.HandleApp()))

	mux.HandleFunc("GET /api/healthz", s.HandleGetHealth)

	// metrics
	mux.HandleFunc("GET /api/metrics", s.HandleGetMetrics)
	mux.HandleFunc("GET /admin/metrics/", s.HandleGetAdminMetrics)
	mux.HandleFunc("/api/reset", s.HandleResetMetrics)

	// api chirps
	mux.HandleFunc("POST /api/chirps", s.HandlePostChirps)
	mux.HandleFunc("GET /api/chirps", s.HandleGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirpId}", s.HandleGetChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpId}", s.HandleDeleteChirp)

	// api users
	mux.HandleFunc("POST /api/users", s.HandlePostUsers)
	mux.HandleFunc("PUT /api/users", s.HandlePutUsers)

	//api auth
	mux.HandleFunc("POST /api/login", s.HandlePostLogin)
	mux.HandleFunc("POST /api/refresh", s.HandlePostRefresh)
	mux.HandleFunc("POST /api/revoke", s.HandlePostRevoke)

	//api webhooks
	mux.HandleFunc("POST /api/polka/webhooks", s.HandlePostPolkaWebhook)

	return mux
}

func (s *Server) HandleApp() http.Handler {
	return http.StripPrefix("/app", http.FileServer(http.Dir(".")))
}

func (s *Server) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (s *Server) HandleGetHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) HandleGetMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hits: %d", s.fileserverHits)))
}

func (s *Server) HandleGetAdminMetrics(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("./admin/metrics/index.html")
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	err = tmpl.Execute(w, s.fileserverHits)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Println(err)
		return
	}
}

func (s *Server) HandleResetMetrics(w http.ResponseWriter, r *http.Request) {
	s.fileserverHits = 0
	w.WriteHeader(http.StatusOK)
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

func (s *Server) HandlePostChirps(w http.ResponseWriter, r *http.Request) {
	token := s.GetToken(r)
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

	res, err := s.db.CreateChirp(Clean(req.Body), id)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusCreated, res)
}

func (s *Server) HandleGetChirps(w http.ResponseWriter, r *http.Request) {
	authorIdParam := r.URL.Query().Get("author_id")
	chirps := []database.Chirp{}
	if authorIdParam == "" {
		allChirps, err := s.db.GetChirps()
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		chirps = allChirps
	} else {
		authorId, err := strconv.Atoi(authorIdParam)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		authorChirps, err := s.db.GetChirpsByAuthorID(authorId)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		chirps = authorChirps
	}
	sortParam := r.URL.Query().Get("sort")
	var sortFunc func(int, int) bool
	switch sortParam {
	case "", "asc":
		sortFunc = func(i, j int) bool {
			return chirps[i].Id < chirps[j].Id
		}
	case "desc":
		sortFunc = func(i, j int) bool {
			return chirps[i].Id > chirps[j].Id
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sort.Slice(chirps, sortFunc)
	respondWithJSON(w, http.StatusOK, chirps)
}

func (s *Server) HandleGetChirp(w http.ResponseWriter, r *http.Request) {
	chirpId, err := strconv.Atoi(r.PathValue("chirpId"))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	chirp, err := s.db.GetChirp(chirpId)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	respondWithJSON(w, http.StatusOK, chirp)
}

func (s *Server) HandlePostUsers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := s.db.CreateUser(req.Email, req.Password)
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

func (s *Server) HandlePostLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := s.db.GetUserByEmail(req.Email)
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

	signedJWTToken, err := s.GenerateJWTToken(user)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	refreshToken, err := s.db.CreateRefreshToken(user.Id)
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

func (s *Server) HandlePutUsers(w http.ResponseWriter, r *http.Request) {
	token := s.GetToken(r)

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

	user, err := s.db.UpdateUser(id, req.Email, req.Password)
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

func (s *Server) GenerateJWTToken(user database.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 3600)),
		Subject:   fmt.Sprint(user.Id),
	})

	signedToken, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", err
	}

	return signedToken, err
}

func (s *Server) HandlePostRefresh(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:]
	user, err := s.db.GetUserByToken(tokenString)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	newToken, err := s.GenerateJWTToken(user)
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

func (s *Server) HandlePostRevoke(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")[7:]
	if err := s.db.RevokeRefreshToken(tokenString); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) GetToken(r *http.Request) *jwt.Token {
	tokenString := r.Header.Get("Authorization")[7:]
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil
	}
	return token
}

func (s *Server) HandleDeleteChirp(w http.ResponseWriter, r *http.Request) {
	token := s.GetToken(r)
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

	chirp, err := s.db.GetChirp(chirpId)
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

	if err := s.db.DeleteChirp(chirpId); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) HandlePostPolkaWebhook(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.Contains(authHeader, "ApiKey ") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if authHeader[7:] != s.polkaAPIKey {
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

	user, err := s.db.GetUserByID(req.Data.UserId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !user.IsChirpyRed {
		if err := s.db.UpdateUserChirpyRed(req.Data.UserId, true); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
