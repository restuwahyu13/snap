package snap

import (
	"crypto"
	"crypto/hmac"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type (
	Token interface {
		Sign(req Sign) (res TokenResponse)
	}

	token struct{}
)

func NewToken() Token {
	return token{}
}

func (p token) Sign(req Sign) (res TokenResponse) {
	secretKey := req.SecretKey
	jtiKey := fmt.Sprintf("%s:%s:%s", secretKey, req.ClientID, req.Signature)

	hmac512 := hmac.New(crypto.SHA512.New, []byte(jtiKey))
	if _, err := hmac512.Write(req.Claim); err != nil {
		res.Error = err
		return
	}

	aud := secretKey[0:5]
	iss := secretKey[10:15]
	sub := secretKey[20:25]
	jti := string(hmac512.Sum(nil))

	timestamp := time.Now().Format("2006/01/02 15:04:05")
	duration := time.Duration(time.Second * time.Duration(req.Expired))

	jwtIat := time.Now().UTC().Add(-duration)
	jwtExp := time.Now().Add(duration)

	options := jwt.New()
	options.Set(jwt.AudienceKey, aud)
	options.Set(jwt.IssuerKey, iss)
	options.Set(jwt.SubjectKey, sub)
	options.Set(jwt.JwtIDKey, jti)
	options.Set(jwt.ExpirationKey, jwtExp)
	options.Set(jwt.IssuedAtKey, jwtIat)
	options.Set("timestamp", timestamp)

	token, err := jwt.Sign(options, jwt.WithKey(jwa.HS512(), []byte(req.SecretKey)))
	if err != nil {
		res.Error = err
		return
	}

	res.Token = string(token)
	res.Expired = req.Expired
	return
}
