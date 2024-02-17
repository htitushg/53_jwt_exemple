package main

import (
	"53_jwt_exemple/assets"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("my_secret_key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Si la session est valide, renvoie le Token et true, sinon nil et false
func SessionValide(w http.ResponseWriter, r *http.Request) (claims *Claims, stoken string, resultat bool) {
	c, err := r.Cookie("token")
	resultat = false
	stoken = ""
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return claims, stoken, resultat
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return claims, stoken, resultat
	}
	stoken = c.Value
	claims = &Claims{}
	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(stoken, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return claims, stoken, resultat
		}
		w.WriteHeader(http.StatusBadRequest)
		return claims, stoken, resultat
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return claims, stoken, resultat
	}
	//fmt.Printf("time.Until(claims.ExpiresAt.Time)= %v\n", time.Until(claims.ExpiresAt.Time))
	if time.Until(claims.ExpiresAt.Time) <= 0 { //> 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return claims, stoken, resultat
	}

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newSessionToken, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return claims, stoken, resultat
	}

	// Set the new token as the users `token` cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   newSessionToken,
		Expires: expirationTime,
	})
	resultat = true
	return claims, newSessionToken, resultat
}

// Controlleur Home: Affiche le Page publique(home) si la session n'est pas valide, sinon affiche la page privée(index)
func Home(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Home log: UrlPath: %#v\n", r.URL.Path) // testing
	var data assets.Data
	var t *template.Template
	var err error
	claims, stoken, exists := SessionValide(w, r)
	if !exists {
		t, err = template.ParseFiles(assets.Chemin + "templates/home.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	} else {
		// Il nous faut ici rassembler les infos utilisateur
		DJour := time.Now().Format("2006-01-02")
		data.Date_jour = DJour
		data.SToken = stoken
		data.Username = claims.Username
		data.Date_Expire = claims.ExpiresAt.Time

		t, err = template.ParseFiles(assets.Chemin + "templates/index.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	if err = t.Execute(w, data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

// Controlleur Login: Affiche la page de connexion
func Login(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Login log: UrlPath: %#v\n", r.URL.Path)
	var data assets.Data
	var t *template.Template
	var err error
	claims, stoken, exists := SessionValide(w, r)
	if !exists {
		// la session n'est pas valide
		t, err = template.ParseFiles(assets.Chemin + "templates/login.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	} else {
		// la session est valide, Il nous faut ici rassembler les infos utilisateur
		DJour := time.Now().Format("2006-01-02")
		data.Date_jour = DJour
		data.SToken = stoken
		data.Username = claims.Username
		data.Date_Expire = claims.ExpiresAt.Time

		t, err = template.ParseFiles(assets.Chemin + "templates/index.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	if err = t.Execute(w, data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

// traitement login post
func LoginPost(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("LoginPost log: UrlPath: %#v\n", r.URL.Path)
	var creds Credentials
	var err error
	var data assets.Data
	var t *template.Template
	creds.Username = r.FormValue("pseudo")
	creds.Password = r.FormValue("passid")

	// Get the expected password from our in memory map
	expectedPassword, ok := users[creds.Username]

	// If a password exists for the given user
	// AND, if it is the same as the password we received, the we can move ahead
	// if NOT, then we return an "Unauthorized" status
	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		t, err = template.ParseFiles(assets.Chemin + "templates/login.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	} else {

		// Declare the expiration time of the token
		// here, we have kept it as 5 minutes
		expirationTime := time.Now().Add(5 * time.Minute)
		// Create the JWT claims, which includes the username and expiry time
		claims := &Claims{
			Username: creds.Username,
			RegisteredClaims: jwt.RegisteredClaims{
				// In JWT, the expiry time is expressed as unix milliseconds
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}

		// Declare the token with the algorithm used for signing, and the claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Create the JWT string
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			// If there is an error in creating the JWT return an internal server error
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Finally, we set the client cookie for "token" as the JWT we just generated
		// we also set an expiry time which is the same as the token itself
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
		DJour := time.Now().Format("2006-01-02")
		data.Username = claims.Username
		data.Date_jour = DJour
		data.SToken = tokenString
		data.Date_Expire = expirationTime

		t, err = template.ParseFiles(assets.Chemin + "templates/index.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	if err := t.Execute(w, data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

// Controlleur AfficheUserInfo: Si la session est valide renvoie vers afficheuserinfo
// Sinon renvoie vers home
func AfficheUserInfo(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("AfficheUserInfo log: UrlPath: %#v\n", r.URL.Path) // testing
	var data assets.Data
	var err error
	var t *template.Template
	_, tokenString, exists := SessionValide(w, r)
	if exists {
		claims := &Claims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		DJour := time.Now().Format("2006-01-02")
		data.Username = claims.Username
		data.Date_jour = DJour
		data.SToken = tokenString
		data.Date_Expire = claims.ExpiresAt.Time
		t, err = template.ParseFiles(assets.Chemin + "templates/afficheuserinfo.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	} else {
		t, err = template.ParseFiles(assets.Chemin + "templates/home.html")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	if err := t.Execute(w, data); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

// Fonction de déconnexion de l'utilisateur
func Logout(w http.ResponseWriter, r *http.Request) {
	// effacez immédiatement le cookie du jeton
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
	t, err := template.ParseFiles(assets.Chemin + "templates/home.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := t.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}

// Controlleur Register: Renvoie vers register pour enregistrement
func Register(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Register log: UrlPath: %#v\n", r.URL.Path) // testing
	var err error
	var t *template.Template
	t, err = template.ParseFiles(assets.Chemin + "templates/register.html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := t.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
}
