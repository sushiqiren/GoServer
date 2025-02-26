package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	password := "mysecretpassword"
	hashedPassword, err := HashPassword(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hashedPassword)

	err = CheckPasswordHash(password, hashedPassword)
	assert.NoError(t, err)

	err = CheckPasswordHash("wrongpassword", hashedPassword)
	assert.Error(t, err)
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "mysecretkey"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "mysecretkey"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	validatedUserID, err := ValidateJWT(token, tokenSecret)
	assert.NoError(t, err)
	assert.Equal(t, userID, validatedUserID)
}

func TestValidateExpiredJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "mysecretkey"
	expiresIn := -time.Hour // Token already expired

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	_, err = ValidateJWT(token, tokenSecret)
	assert.Error(t, err)
}

func TestValidateJWTWithWrongSecret(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "mysecretkey"
	wrongSecret := "wrongsecret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	_, err = ValidateJWT(token, wrongSecret)
	assert.Error(t, err)
}

func TestGetBearerToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer mytoken")

	token, err := GetBearerToken(headers)
	assert.NoError(t, err)
	assert.Equal(t, "mytoken", token)

	headers.Set("Authorization", "Bearer    mytoken   ")
	token, err = GetBearerToken(headers)
	assert.NoError(t, err)
	assert.Equal(t, "mytoken", token)

	headers.Set("Authorization", "bearer mytoken")
	token, err = GetBearerToken(headers)
	assert.NoError(t, err)
	assert.Equal(t, "mytoken", token)

	headers.Set("Authorization", "Bearer")
	_, err = GetBearerToken(headers)
	assert.Error(t, err)

	headers.Set("Authorization", "Token mytoken")
	_, err = GetBearerToken(headers)
	assert.Error(t, err)

	headers.Del("Authorization")
	_, err = GetBearerToken(headers)
	assert.Error(t, err)
}
