package main

import (
	"os"
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
	"go.mongodb.org/mongo-driver/mongo/readconcern"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
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
	u2:= uuid.NewV4()

	return u2.String()
}

func createAccessToken (id string, sessionId interface{}, w http.ResponseWriter) (string) {
	var mySigningKey = []byte("secretString")
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"id": id,
		"sessionId": sessionId.(string),
	})
	
	tokenString, err := token.SignedString(mySigningKey)
	
	if err != nil {
		fmt.Printf("Server error. Access token is not created. \n")
		http.Error(w, "Server error. Access token is not created", 500)
		return ""
	}
	return tokenString
}

func createRefreshToken() (string) {
	return getId()
}


func encodeToken (token string) string {
	data := []byte(token)
	str := base64.StdEncoding.EncodeToString(data)
	return str
}



func decodeToken (encodeStr string, w http.ResponseWriter) (string, bool) {
	token, err := base64.StdEncoding.DecodeString(encodeStr)
	if err != nil {
		fmt.Printf("%q\n Encoding error: ", err)
		http.Error(w, "Server error. Refresh token has not been decoded", 403)
		return "", false
	}
	return  string(token), true
}

func hashToken(token string, w http.ResponseWriter) (string) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(token), 14)
	if err != nil {
		fmt.Printf("Server error. Tokens has not been hashed. \n",  err)
		http.Error(w, "Server error. Tokens has not been created ", 500)
		return ""
	}
    return string(bytes)
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

func parseTokens (r *http.Request) (string, string) {
	cookieRefreshToken, err := r.Cookie("refreshToken")
	cookieAccessToken, err := r.Cookie("accessToken")				
	if err != nil {
		return "", ""
	}
	refreshToken := cookieRefreshToken.Value
	accessToken := cookieAccessToken.Value
	return accessToken, refreshToken
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

func determineListenAddress() (string, error) {
  port := os.Getenv("PORT")
  if port == "" {
    return "", fmt.Errorf("$PORT not set")
  }
  return ":" + port, nil
}

func main() {	
	addres, err := determineListenAddress()
	if err != nil {
		log.Fatal("Address: ", err)
	 }
	type Users struct {
		name string 
		token string 
	}	
	ctx, cancel := context.WithTimeout(context.Background(), 36000*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
	  "mongodb+srv://Maxim:***@testtaskgolang.nuqne.mongodb.net/***?retryWrites=true&w=majority",
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

	saveTokenInDB := func(client *mongo.Client, token string, userId string, w http.ResponseWriter) (string) {
		var id string
		collection  := client.Database("Auth").Collection("Users")
		
		wc := writeconcern.New(writeconcern.WMajority())
		rc := readconcern.Snapshot()
		txnOpts := options.Transaction().SetWriteConcern(wc).SetReadConcern(rc)

		session, err := client.StartSession()
		if err != nil {
			panic(err)
		}
		defer session.EndSession(ctx)

		err = mongo.WithSession(ctx, session, func(sessionContext mongo.SessionContext) (error) {
			if err = session.StartTransaction(txnOpts); err != nil {
				return err
			}
			insertResult, err := collection.InsertOne(ctx,  bson.D{
				{Key: "userId", Value: userId},
				{Key: "token", Value: token},
			})
			if err != nil {
				return err
			}
			fmt.Println(insertResult.InsertedID)
			if err = session.CommitTransaction(sessionContext); err != nil {
				return err
			}
			id = getId(insertResult)
			return nil
		})

		if err != nil {
		    if abortErr := session.AbortTransaction(ctx); abortErr != nil {
				fmt.Printf("Server error. Tokens has not been saved in db. \n", abortErr, "/n")
				http.Error(w, "Server error. Tokens has not been saved in db", 500)
			}
			fmt.Printf("Server error. Tokens has not been saved in db2. \n", err, "/n")
			return ""
		}
		return id	
	}
	
	findUser := func(client *mongo.Client, sessionId string) (Person, error) {
		var person Person
		collection  := client.Database("Auth").Collection("Users")
		
		wc := writeconcern.New(writeconcern.WMajority())
		rc := readconcern.Snapshot()
		txnOpts := options.Transaction().SetWriteConcern(wc).SetReadConcern(rc)

		session, err := client.StartSession()
		if err != nil {return person, err}
		defer session.EndSession(ctx)
		
		err = mongo.WithSession(ctx, session, func(sessionContext mongo.SessionContext) (error) {
			if err = session.StartTransaction(txnOpts); err != nil {
				return err
			}
			docID, err := primitive.ObjectIDFromHex(sessionId)
			
			err = collection.FindOne(ctx, bson.M{"_id": docID}).Decode(&person)
			if  err != nil {return  err}
			return nil
		})
		if err != nil {
		    if abortErr := session.AbortTransaction(ctx); abortErr != nil {
				fmt.Printf("User dont found. \n", abortErr, "\n")
				return person,  err
			}
			
		}
		return person,  err	
	}
	
	deleteToken := func(client *mongo.Client, sessionId string) (bool) {
		docID, err := primitive.ObjectIDFromHex(sessionId)
		collection  := client.Database("Auth").Collection("Users")
		
		wc := writeconcern.New(writeconcern.WMajority())
		rc := readconcern.Snapshot()
		txnOpts := options.Transaction().SetWriteConcern(wc).SetReadConcern(rc)

		session, err := client.StartSession()
		if err != nil {
			return false
		}
		defer session.EndSession(ctx)
		
		err = mongo.WithSession(ctx, session, func(sessionContext mongo.SessionContext) (error) {
			if err = session.StartTransaction(txnOpts); err != nil {
				return err
			}
			
			deleteResult, err := collection.DeleteOne(ctx, bson.M{"_id": docID})
			if err != nil {
				fmt.Printf("The token have not been deleted \n", err, "\n")	
				return err
			}
			fmt.Printf("Deleted %v document in the Auth collection\n", deleteResult.DeletedCount)
			return nil
		})
		
		if err != nil {
			if abortErr := session.AbortTransaction(ctx); abortErr != nil {
				fmt.Printf("Abborted error. \n", abortErr, "\n")	
			}
			return false
		}
		return true
	}
	
	deleteAllToken := func(client *mongo.Client, userId string) (bool) {
		collection  := client.Database("Auth").Collection("Users")
		wc := writeconcern.New(writeconcern.WMajority())
		rc := readconcern.Snapshot()
		txnOpts := options.Transaction().SetWriteConcern(wc).SetReadConcern(rc)

		session, err := client.StartSession()
		if err != nil {
			return false
		}
		defer session.EndSession(ctx)
		
		err = mongo.WithSession(ctx, session, func(sessionContext mongo.SessionContext) (error) {
			if err = session.StartTransaction(txnOpts); err != nil {
				return err
			}
			deleteResult, err := collection.DeleteMany(ctx, bson.M{"userId": userId})
			if err != nil {
				fmt.Printf("The tokens have not been deleted \n", err, "\n")	
				return err
			}
			fmt.Printf("Deleted %v documents in the Auth collection\n", deleteResult.DeletedCount)
			return nil
		})	
		
		if err != nil {
			if abortErr := session.AbortTransaction(ctx); abortErr != nil {
				fmt.Printf("Abborted error. \n", abortErr, "\n")	
			}
			return false
		}
		return true
		
	}
	
	
	isSessionInterrupted := func (w http.ResponseWriter, r *http.Request) {
		path := "./static/index.html"
		accessToken, refreshToken := parseTokens(r)
		if accessToken == "" || refreshToken == "" {
			http.ServeFile(w, r, path)
			return
		}
		
		claims, err := getClaims(accessToken)
		if err != nil {
			removeCookie(w, "accessToken")
			removeCookie(w, "refreshToken")
			http.ServeFile(w, r, path)
			return
		}

		user, err := findUser(client, claims.SessionId)
		if err != nil || user.UserId == "" {
			removeCookie(w, "accessToken")
			removeCookie(w, "refreshToken")
			http.ServeFile(w, r, path)
			return
		}
		http.ServeFile(w, r, path)
	}
	
	f0 := func(w http.ResponseWriter, r *http.Request) {
		isSessionInterrupted(w, r)
	}
	
	f1 := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var person Person
			err := json.NewDecoder(r.Body).Decode(&person)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if person.UserId != "" {
				refreshToken := createRefreshToken()
				
				hashRefreshToken := hashToken(refreshToken, w)
				if hashRefreshToken == "" {return}
				sessionId := saveTokenInDB(client, hashRefreshToken, person.UserId, w)
				
				if sessionId == "" {return}
				accessToken := createAccessToken(person.UserId, sessionId, w)
				fmt.Printf("/person.UserId \n", person.UserId)
				if accessToken == "" {return}
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
			accessToken, refreshToken := parseTokens(r)
			if accessToken == "" || refreshToken == "" {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				http.Error(w, "Token is bad", 403)
				return
			}
			
			decodedToken, decoded := decodeToken(refreshToken, w)
			if decoded  == false {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				return
			}

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
				
				hashRefreshToken := hashToken(refreshToken, w)
				if hashRefreshToken == "" {return}
				
				sessionId := saveTokenInDB(client, hashRefreshToken, person.UserId, w)
				if sessionId == "" {return}
				
				accessToken := createAccessToken(person.UserId, sessionId, w)
				if accessToken == "" {return}
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
			accessToken, refreshToken := parseTokens(r)
			if accessToken == "" || refreshToken == "" {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				http.Error(w, "Token is bad", 403)
				return
			}
			
			decodedToken, decoded := decodeToken(refreshToken, w)
			if decoded  == false {
				removeCookie(w, "accessToken")
				removeCookie(w, "refreshToken")
				return
			}
			
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
	
	http.HandleFunc("/", f0)
	http.HandleFunc("/releaseTokens", f1)
	http.HandleFunc("/refresh", f2)
	http.HandleFunc("/delete", f3)
	http.HandleFunc("/deleteAll", f4)
	
	fmt.Printf("port: ", addres)
	
	errorListen := http.ListenAndServe(addres, nil)
	fmt.Printf("errorListen: ", errorListen)
	if errorListen != nil {
		log.Fatal(errorListen)
	}
}

