package main

import (
	"53_jwt_exemple/assets"
	"fmt"
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
	// start the server on port 8000
	log.Fatal(http.ListenAndServe(":8000", nil))
}
