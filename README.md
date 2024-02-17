JWT
https://www.sohamkamani.com/golang/jwt-authentication/

Si vous savez déjà comment fonctionne JWT et que vous souhaitez simplement voir l'implémentation, vous pouvez passer directement ou consulter le code source sur Github.

Le jeton Web JSON (JWT) vous permet d'authentifier vos utilisateurs de manière apatride, sans stocker aucune information les concernant sur le système lui-même (contrairement à l'authentification basée sur la session ).

## Le format JWT

Prenons l'exemple d'un utilisateur appelé user1, essayant de se connecter à une application ou à un site Web : une fois qu'il aura réussi, il recevra un jeton qui ressemble à ceci :

```bash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIxIiwiZXhwIjoxNTQ3OTc0MDgyfQ.2Ye5_w1z3zpD4dSGdRp3s98ZipCNQqmsHRB9vioOx54
```

Il s'agit d'un JWT composé de trois parties (séparées par .) :

### La première partie est l'en-tête

( eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9).
L'en-tête précise des informations comme l'algorithme utilisé pour générer la signature (la troisième partie). Cette partie est assez standard et est la même pour tout JWT utilisant le même algorithme.

### La deuxième partie est la charge utile

( eyJ1c2VybmFtZSI6InVzZXIxIiwiZXhwIjoxNTQ3OTc0MDgyfQ),
qui contient des informations spécifiques à l'application (dans notre cas, il s'agit du nom d'utilisateur), ainsi que des informations sur l'expiration et la validité du jeton.

### La troisième partie est la signature

( 2Ye5_w1z3zpD4dSGdRp3s98ZipCNQqmsHRB9vioOx54).
Il est généré en combinant et en hachant les deux premières parties avec une clé secrète.
Notez que l’en-tête et la charge utile ne sont pas cryptés – ils sont simplement codés en base64. Cela signifie que n'importe qui peut les décoder à l'aide d'un décodeur base64.

Par exemple, si nous décodons l'en-tête en texte brut, nous verrons le contenu ci-dessous :

```go
{ "alg": "HS256", "typ": "JWT" }
```

Si vous utilisez Linux ou Mac OS, vous pouvez également exécuter l'instruction suivante sur le terminal :

```bash
echo eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 | base64 -d
```

De même, le contenu de la charge utile est :

```go
{ "username": "user1", "exp": 1547974082 }
```

## Comment fonctionne la signature JWT

Donc, si l’en-tête et la signature d’un JWT sont accessibles à tous, qu’est-ce qui rend réellement un JWT sécurisé ? La réponse réside dans la façon dont la troisième partie (la signature) est générée.

Prenons l'exemple d'une application qui souhaite émettre un JWT à un utilisateur (par exemple, user1) qui s'est connecté avec succès.

La création de l'en-tête et de la charge utile est assez simple : l'en-tête est corrigé pour notre cas d'utilisation, et l'objet JSON de charge utile est formé en définissant l'ID utilisateur et le délai d'expiration en millisecondes Unix.

L'application émettant le jeton aura également une clé, qui est une valeur secrète et connue uniquement de l'application elle-même.

Les représentations base64 de l'en-tête et de la charge utile sont ensuite combinées avec la clé secrète puis transmises via un algorithme de hachage (dans ce cas, son HS256, comme mentionné dans l'en-tête).

![alt text](./image.png)

Les détails de la façon dont l'algorithme est implémenté sortent du cadre de cet article, mais la chose importante à noter est qu'il s'agit d'un moyen unique, ce qui signifie que nous ne pouvons pas inverser l'algorithme et obtenir les composants qui ont servi à créer la signature - donc notre la clé secrète reste secrète.

## Vérifier un JWT

Pour vérifier un JWT, le serveur génère à nouveau la signature en utilisant l'en-tête et la charge utile du JWT entrant, ainsi que sa clé secrète. Si la signature nouvellement générée correspond à celle du JWT, alors le JWT est considéré comme valide.

Désormais, si vous essayez d'émettre un faux jeton, vous pouvez facilement générer l'en-tête et la charge utile, mais sans connaître la clé, il n'y a aucun moyen de générer une signature valide. Si vous essayez de falsifier la charge utile existante d'un JWT valide, les signatures ne correspondront plus.
![alt text](./jwt-verification.png)
De cette manière, le JWT agit comme un moyen d'autoriser les utilisateurs de manière sécurisée, sans stocker aucune information (outre la clé) sur le serveur émetteur.

## Implémentation en Go

Maintenant que nous avons vu comment fonctionne l'authentification basée sur JWT, implémentons-la à l'aide de Go.

### Création du serveur HTTP

Commençons par initialiser le serveur HTTP avec les routes requises :

```go
package main

import (
	"log"
	"net/http"
)

func main() {
	fmt.Printf("Main Chemin= %s\n", assets.Chemin+"assets/") //
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(assets.Chemin+"assets/"))))
	http.HandleFunc("/", Home) // page publique
	http.HandleFunc("/Login", Login)
	http.HandleFunc("/LoginPost", LoginPost)
	http.HandleFunc("/AfficheUserInfo", AfficheUserInfo)
	http.HandleFunc("/Logout", Logout)
	http.HandleFunc("/Register", Register)
	// Démarrage du serveur sur le port 8000
	log.Fatal(http.ListenAndServe(":8000", nil))
}

```

Nous pouvons maintenant définir les itinéraires LoginPost et Welcome.

### Gestion de la connexion des utilisateurs

Le Login itinéraire prendra les informations d'identification des utilisateurs et les transmettra au LoginPost itinéraire et après vérification le connectera. Définissons d'abord les données des utilisateurs, ainsi que certains types pour représenter les informations d'identification et les revendications JWT :

```go
import (
	//...
	// import the jwt-go library
	"github.com/golang-jwt/jwt/v5"
	//...
)

// Create the JWT key used to create the signature
var jwtKey = []byte("my_secret_key")

// For simplification, we're storing the users information as an in-memory map in our code
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Create a struct to read the username and password from the request body
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// Create a struct that will be encoded to a JWT.
// We add jwt.RegisteredClaims as an embedded type, to provide fields like expiry time
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

```

Donc pour l'instant, il n'y a que deux utilisateurs valides dans notre application : user1, et user2. Dans une application réelle, les informations utilisateur seraient stockées dans une base de données et le mot de passe serait haché et stocké dans une colonne distincte. Nous utilisons ici une carte codée en dur pour plus de simplicité.

Ensuite, nous pouvons écrire le LoginPost gestionnaire HTTP. Pour cet exemple, nous utilisons la bibliothèque golang-jwt/jwt pour nous aider à créer et vérifier les jetons JWT.

```go
// Create the LoginPost handler
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

```

💡 Dans cet exemple, la jwtKey variable est utilisée comme clé secrète pour la signature JWT. Cette clé doit être conservée en sécurité sur le serveur et ne doit être partagée avec personne en dehors du serveur. Normalement, cela est stocké dans un fichier de configuration et non dans le code source. Nous utilisons ici une valeur codée en dur pour plus de simplicité.

Si un utilisateur se connecte avec les informations d'identification correctes, ce gestionnaire définira alors un cookie côté client avec la valeur JWT. Une fois qu'un cookie est défini sur un client, il est désormais envoyé avec chaque demande. Nous pouvons maintenant écrire notre gestionnaire de bienvenue pour gérer les informations spécifiques à l'utilisateur.

### Gestion des routes de post-authentification

Maintenant que tous les clients connectés ont des informations de session stockées de leur côté sous forme de cookies, nous pouvons les utiliser pour :

Authentifier les demandes ultérieures des utilisateurs
Obtenir des informations sur l'utilisateur qui fait la demande
Écrivons notre fonction de vérification : la session est elle valide ?
Elle est appelée lors de toute action de l'utilisateur
Cette fonction vérifie si une session est en cours, et si elle n'a pas expiré, elle renvoie les informations nécessaires, et met à jour le jeton avec une nouvelle date d'expiration:

```go
func SessionValide(w http.ResponseWriter, r *http.Request) (claims *Claims, stoken string, resultat bool) {
	c, err := r.Cookie("token")
	resultat = false
	stoken = ""
	if err != nil {
		if err == http.ErrNoCookie {
			// Si le cookie n'est pas défini, renvoie un statut non autorisé
			w.WriteHeader(http.StatusUnauthorized)
			return claims, stoken, resultat
		}
		// Pour tout autre type d'erreur, renvoie un statut de requête incorrect
		w.WriteHeader(http.StatusBadRequest)
		return claims, stoken, resultat
	}
	stoken = c.Value
	claims = &Claims{}
	/*Analysez la chaîne JWT et stockez le résultat dans « claims ».
 	Notez que nous transmettons également la clé dans cette méthode. Cette méthode renverra une erreur
 	si le token n'est pas valide (s'il a expiré selon le délai d'expiration que nous avons fixé lors de la connexion),
 	ou si la signature ne correspond pas*/
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
	//On vérifie que la session n'est pas expirée
	//fmt.Printf("time.Until(claims.ExpiresAt.Time)= %v\n", time.Until(claims.ExpiresAt.Time))
	if time.Until(claims.ExpiresAt.Time) <= 0 { //> 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return claims, stoken, resultat
	}
	/*Dans cet exemple, nous avons fixé un court délai d'expiration de cinq minutes. Nous ne devons pas nous attendre à ce que l'utilisateur se connecte toutes les cinq minutes si son token expire.*/
	// Maintenant, créons un nouveau token, avec un délai d'expiration renouvelé
	expirationTime := time.Now().Add(5 * time.Minute)
	claims.ExpiresAt = jwt.NewNumericDate(expirationTime)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newSessionToken, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return claims, stoken, resultat
	}

	// Définir le nouveau jeton comme cookie « jeton » de l'utilisateur
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   newSessionToken,
		Expires: expirationTime,
	})
	resultat = true
	return claims, newSessionToken, resultat
}

```

### Gestion de la déconnexion

La déconnexion peut être délicate lorsqu'il s'agit d'authentification basée sur JWT, car notre application est censée être sans état, ce qui signifie que nous ne stockons aucune information sur les jetons JWT émis sur notre serveur.

Les seules informations dont nous disposons sont notre clé secrète et l'algorithme utilisé pour encoder et décoder le JWT. Si un token satisfait à ces exigences, il est considéré comme valide par notre application.

C'est pourquoi la méthode recommandée pour gérer la déconnexion est de fournir des jetons avec un délai d'expiration court et d'exiger que le client continue d'actualiser le jeton. De cette façon, nous pouvons garantir que pendant une période d'expiration T, la durée maximale pendant laquelle un utilisateur peut rester connecté sans l'autorisation explicite de l'application est T de quelques secondes.

Une autre option consiste à créer une /logout route qui efface le cookie du jeton de l'utilisateur, afin que les requêtes ultérieures ne soient pas authentifiées :

```go
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
```

Cependant, il s'agit d'une implémentation côté client et peut être contournée si le client décide de ne pas suivre les instructions et de supprimer le cookie.

Nous pouvons également stocker les JWT que nous souhaitons invalider sur le serveur, mais cela rendrait notre application avec état.

### Exécuter notre application

Pour exécuter cette application, créez et exécutez le binaire Go :

```bash
go build
./jwt-go-example

```

Désormais, vous pouvez, en utilisant votre navigateur Web :

```bash
http://localhost:8000
```
Vous obtiendrez une page vous invitant à vous connecter. Il faudra entrer les informations suivantes :
"username":"user1","password":"password1"



Vous obtiendrez alors la fenêtre d'affichage privée avec le nom de l'utilisateur, le jeton et la date d'expiration du jeton.

Vous avez aussi la possibilité d'afficher le profil de l'utilisateur. Vérifiez que le jeton à chaque action est mis à jour.

Vous pouvez trouver le code source de travail pour cet exemple ici(https://github.com/sohamkamani/jwt-go-example) .

