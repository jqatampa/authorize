package authorize

import (
  "net/http"
  "github.com/dgrijalva/jwt-go"
  "time"
  "fmt"
)

type Authorize struct {
  Options Options
}

type Options struct {
  PublicKey []byte
  SigningKey []byte
  SigningMethod string
  Claims map[string]string
}

func NewAuthorize(o Options) *Authorize {
  return &Authorize {
    Options: o,
  }
}

func RejectAuth(rw http.ResponseWriter) {
  rw.WriteHeader(http.StatusUnauthorized)
  rw.Write([]byte("You are not Authorized for this request"))
}

func (a *Authorize) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
  if r.Header.Get("Authorization") == "" {
    RejectAuth(rw)
    return
  }
  token, _ := jwt.ParseFromRequest(r, func(token *jwt.Token) (interface{}, error) {
    return []byte(a.Options.PublicKey), nil
  })
  if !token.Valid {
    RejectAuth(rw)
    return
  }
  if a.Options.Claims != nil {
    if token.Claims == nil {
      RejectAuth(rw)
      return
    }
    for key, optionVal := range a.Options.Claims {
      tokenVal := token.Claims[key]
      fmt.Println("Token: %v; Check: %v", tokenVal, optionVal)
      if tokenVal == nil || tokenVal.(string) != optionVal {
        RejectAuth(rw)
        return
      }
    }
  }
  next(rw, r)
}

func WriteToken(rw http.ResponseWriter, options Options) {
  // Create the token
  token := jwt.New(jwt.GetSigningMethod(options.SigningMethod))
  // Set some claims
  for k,v := range options.Claims {
    token.Claims[k] = v
  }
  token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
  // Sign and get the complete encoded token as a string
  tokenString, _ := token.SignedString(options.SigningKey)
  rw.Write([]byte(tokenString))
}