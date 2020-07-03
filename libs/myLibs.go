package main

import (
	"fmt"
	"io"
	"net/http"
	"log"
	"time"
	"context"
	"github.com/satori/go.uuid"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)	

func addCookie(w http.ResponseWriter, name, value string) {
	cookie := http.Cookie{
		Name:    name,
		Value:   value,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}

func main() {	
	
	type Users struct {
		name string 
		token string 
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
	  "mongodb+srv://Maxim:MaximTestGolang@testtaskgolang.nuqne.mongodb.net/testTaskGolang?retryWrites=true&w=majority",
	))
	if err != nil { log.Fatal(err) }

	fmt.Println("Connected to MongoDB!")
	collection  := client.Database("Auth").Collection("Users")

	insertResult, err := collection.InsertOne(ctx,  bson.D{
    {Key: "name", Value: "The Polyglot Developer Podcast"},
    {Key: "token", Value: "Nic Raboy"}})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Inserted a single document: ", insertResult)
	
	
	f1 := func(w http.ResponseWriter, req *http.Request) {
		
		token, err := getToken() // добавить обработчик на ошибку!
		if err != nil {
			log.Fatal(err)
		}
		addCookie(w, "token", token)
		io.WriteString(w, "Hello! #1!\n")
		//fmt.Printf("Token: ", token )
		fmt.Printf("Token check: ",  checkToken(req))
		/*tokenClaims, errParse := parseToken(token)
		if errParse != nil {
			log.Fatal(errParse)
		}
		fmt.Printf("Token Parsed: ",  tokenClaims.Id)*/
		
	}
	
	f2 := func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "GUID rout!\n")
	}
	
	http.HandleFunc("/", f1)
	http.HandleFunc("/GUID", f2)

	http.ListenAndServe(":3000", nil)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

