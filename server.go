package main

import (
	"fmt"
	"log"
	"time"
	"regexp"
	"strings"
	"context"
	"net/http"
	"encoding/json"
	"encoding/base64"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson/primitive"
)	

type Claims struct {
	Id string `json:"id"`
	UserId string `json:"id"`
	SessionId string `json:"sessionId"`
	jwt.StandardClaims
}

type tokenPair struct {
	access string 
	refresh string
}

type Person struct {
    UserId string
	Token string
	Id primitive.ObjectID `bson:"_id"`
}

func getId () string {
	u1 := uuid.Must(uuid.NewV4())
	return u1.String()
}

func createAccessToken (id string, sessionId interface{}) (string, error) {
	var mySigningKey = []byte("secretString")
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"id": id,
		"sessionId": sessionId.(string),
	})
	
	tokenString, err := token.SignedString(mySigningKey)
	return tokenString, err
}

func createRefreshToken() (string) {
	return getId()
}


func encodeToken (token string) string {
	data := []byte(token)
	str := base64.StdEncoding.EncodeToString(data)
	return str
}



func decodeToken (encodeStr string) (string, bool) {
	token, err := base64.StdEncoding.DecodeString(encodeStr)
	if err != nil {
		fmt.Printf("%q\n Encoding error: ", err)
		return "", false
	}
	return  string(token), true
}

func hashToken(token string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(token), 14)
    return string(bytes), err
}

func compareTokens (hashedToken string, refreshToken string) bool {
    byteHash := []byte(hashedToken)
    err := bcrypt.CompareHashAndPassword(byteHash, []byte(refreshToken))
    if err != nil {
        log.Println(err)
        return false
    }
    return true
}

func checkToken (token string) (bool) {
	var jwtKey = []byte("secretString")

	claims := &Claims{}
	fmt.Printf("Token: ", token )
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			fmt.Printf("http.StatusUnauthorized")
			return false
		}
		fmt.Printf("http.StatusBadRequest")
		return false
	}
	if !tkn.Valid {
		fmt.Printf("http.StatusUnauthorized")
		return false
	}
	return true
}

func getClaims (token string) (*Claims, error) {
	var jwtKey = []byte("secretString")
	claims := &Claims{}
	fmt.Printf("Token: ", token )
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	fmt.Printf("",tkn)
	return claims, err
}

func addCookie(w http.ResponseWriter, name string, value string) {
	cookie := http.Cookie{Name: name, Value: value, HttpOnly: true}
	http.SetCookie(w, &cookie)
}

func removeCookie(w http.ResponseWriter, name string) {
	cookie := http.Cookie{Name: name, Value: "deleted", Expires: time.Unix(1414414788, 1414414788000)}
	http.SetCookie(w, &cookie)
}


func main() {	
	
	type Users struct {
		name string 
		token string 
	}	
	ctx, cancel := context.WithTimeout(context.Background(), 3600*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
	  "mongodb+srv://Maxim:******@testtaskgolang.nuqne.mongodb.net/*******?retryWrites=true&w=majority",
	))
	if err != nil { log.Fatal(err) }

	fmt.Println("Connected to MongoDB!")

	getId := func (insertResult *mongo.InsertOneResult) string {
		stringObjectID := insertResult.InsertedID.(primitive.ObjectID)
		stringObjectId := stringObjectID.String()
		re := regexp.MustCompile(`"[0-9A-Fa-z]+`)
		id := re.FindString(stringObjectId)
		s := strings.SplitAfter(id, "\"")
		return s[1]
	}

	saveTokenInDB := func(client *mongo.Client, token string, userId string) (string, error) {
		collection  := client.Database("Auth").Collection("Users")
		
		insertResult, err := collection.InsertOne(ctx,  bson.D{
			{Key: "userId", Value: userId},
			{Key: "token", Value: token},
		})
		
		if err != nil {
			fmt.Printf("Error DB \n", err, "\n")
			return "", err
		}
		id := getId(insertResult)
		return id, err
	
	}
	
	findUser := func(client *mongo.Client, sessionId string) (Person, error) {
		var person Person
		docID, err := primitive.ObjectIDFromHex(sessionId)
		
		collection  := client.Database("Auth").Collection("Users")
		err = collection.FindOne(ctx, bson.M{"_id": docID}).Decode(&person)
		if  err != nil {
			return person, err
		}
		
		return person, err
	}
	
	deleteToken := func(client *mongo.Client, sessionId string) (bool) {
		docID, err := primitive.ObjectIDFromHex(sessionId)
		collection  := client.Database("Auth").Collection("Users")

		deleteResult, err := collection.DeleteOne(ctx, bson.M{"_id": docID})
		if err == nil {
			fmt.Printf("Deleted %v document in the Auth collection\n", deleteResult.DeletedCount)
			return true
		}

		return false
	}
	
	deleteAllToken := func(client *mongo.Client, userId string) (bool) {
		collection  := client.Database("Auth").Collection("Users")
		deleteResult, err := collection.DeleteMany(ctx, bson.M{"userId": userId})
		if err == nil {
			fmt.Printf("Deleted %v documents in the Auth collection\n", deleteResult.DeletedCount)
			return true
		}

		return false
	}
	
	f1 := func(w http.ResponseWriter, r *http.Request) {
		
		if r.Method == "POST" {
			var person Person
			fmt.Printf("/releaseTokens \n", )
			err := json.NewDecoder(r.Body).Decode(&person)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			 if person.UserId != "" {
				refreshToken := createRefreshToken()
				
				hashRefreshToken, err := hashToken(refreshToken)
				if err != nil {
					fmt.Printf("Server error. Tokens has not been hashed. \n",  err)
					http.Error(w, "Server error. Tokens has not been created ", 500)
					return
				}
				
				sessionId, err := saveTokenInDB(client, hashRefreshToken, person.UserId)
				if err != nil {
					fmt.Printf("Server error. Tokens has not been saved in db. \n")
					http.Error(w, "Server error. Tokens has not been saved in db", 500)
					return
				}
				accessToken, err := createAccessToken(person.UserId, sessionId)
				if err != nil {
					fmt.Printf("Server error. Access token is not created. \n")
					http.Error(w, "Server error. Access token is not created", 500)
					return
				}
				addCookie(w, "accessToken", accessToken)
				addCookie(w, "refreshToken", encodeToken(refreshToken))
				w.WriteHeader(204)
				
			 } else  {
				fmt.Printf("UserId is apsent. \n")
				http.Error(w, "UserId not found", 400)
				return
			 }
			 
		} else {
			http.Error(w, "Page not found", 404)
		}
	}
	
	f2 := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var person Person
			err := json.NewDecoder(r.Body).Decode(&person)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			
			cookieRefreshToken, err := r.Cookie("refreshToken")
			cookieAccessToken, err := r.Cookie("accessToken")				
			if err != nil {
				http.Error(w, " Token not found", 403)
				return
			}
			refreshToken := cookieRefreshToken.Value
			decodedToken, decoded := decodeToken(refreshToken)
			if decoded  == false {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				http.Error(w, "Server error. Refresh token has not been decoded", 403)
				return
			}
			accessToken := cookieAccessToken.Value
			claims, err := getClaims(accessToken)
			
			if err != nil {
				http.Error(w, "Access token has not been decoded", 500)
				return
			}
			
			user, err := findUser(client, claims.SessionId)

			if err != nil {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				http.Error(w, "User not found", 500)
				return
			}
			
			isEqual := compareTokens(user.Token ,decodedToken)
			fmt.Printf("isEqual", isEqual, "\n")
			if isEqual == true {
				deleted := deleteToken(client, claims.SessionId);
				if deleted != true {
					fmt.Printf("Server error. Tokens has not been hashed. \n",  err)
					http.Error(w, "\nServer error. Tokens has not been deleted from db ", 500)
					return
				}
				refreshToken := createRefreshToken()
				
				hashRefreshToken, err := hashToken(refreshToken)
				if err != nil {
					fmt.Printf("Server error. Tokens has not been hashed. \n",  err)
					http.Error(w, "Server error. Tokens has not been created ", 500)
					return
				}
				
				sessionId, err := saveTokenInDB(client, hashRefreshToken, person.UserId)
				if err != nil {
					fmt.Printf("Server error. Tokens has not been saved in db. \n")
					http.Error(w, "Server error. Tokens has not been saved in db", 500)
					return
				}
				accessToken, err := createAccessToken(person.UserId, sessionId)
				if err != nil {
					fmt.Printf("Server error. Access token is not created. \n")
					http.Error(w, "Server error. Access token is not created", 500)
					return
				}
				addCookie(w, "accessToken", accessToken)
				addCookie(w, "refreshToken", encodeToken(refreshToken))
				w.WriteHeader(204)
			} else {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				fmt.Printf("Token is bad. \n")
				http.Error(w, "Token is bad", 400)
				return
			}

		} else {
			http.Error(w, "Page not found", 404)
		}
	}
	
	f3 := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			cookieRefreshToken, err := r.Cookie("refreshToken");
			cookieAccessToken, err := r.Cookie("accessToken")				
			if err  != nil {
				http.Error(w, "Server error. Token not passed", 403)
				return
			}
			refreshToken := cookieRefreshToken.Value
			decodedToken, decoded := decodeToken(refreshToken)
			if decoded  == false {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				http.Error(w, "Server error. Refresh token has not been decoded", 403)
				return
			}
			
			accessToken := cookieAccessToken.Value
			claims, err := getClaims(accessToken)
			
			if err != nil {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				http.Error(w, "Access token has not been decoded", 403)
				return
			}
			
			user, err := findUser(client, claims.SessionId)
			if err != nil {
				http.Error(w, "User not found", 500)
				return
			}
			
			isEqual := compareTokens(user.Token ,decodedToken)
			if isEqual == true {
				deleted := deleteToken(client, claims.SessionId);
				if deleted == true {
					removeCookie(w, "accessToken")
					removeCookie(w, "refreshToken")
					w.WriteHeader(204)
					
					return
				}
				http.Error(w, "Server error. Tokens has not been deleted ", 500)
			} else {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				fmt.Printf("Token is bad. \n")
				http.Error(w, "Token is bad", 403)
				return
			}
		} else {
			http.Error(w, "Page not found", 404)
		}
	}
	
	f4 := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			fmt.Printf("/DELETE", "\n")
			var person Person
			err := json.NewDecoder(r.Body).Decode(&person)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cookieAccessToken, err := r.Cookie("accessToken")
			if err != nil {
				http.Error(w, "User not sign in", 403)
				return
			}
			
			accessToken := cookieAccessToken.Value
			isValidAccessToken := checkToken(accessToken)
			if isValidAccessToken == false {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				http.Error(w, "Access token not valid", 403)
				return
			}
						
			deleted := deleteAllToken(client, person.UserId)
			if deleted == true {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				w.WriteHeader(204)
				return
			}
			http.Error(w, "Tokens have not been removed", 500)
			return
		} else {
			http.Error(w, "Page not found", 404)
		}
	}
	
	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/releaseTokens", f1)
	http.HandleFunc("/refresh", f2)
	http.HandleFunc("/delete", f3)
	http.HandleFunc("/deleteAll", f4)

	http.ListenAndServe(":3000", nil)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

