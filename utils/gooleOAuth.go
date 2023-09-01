package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"server/initializers"
	"time"
)

type GoogleOAuthToken struct {
	AccessToken string
	IDToken     string
}



func GetGoogleOAuthToken(code string) (*GoogleOAuthToken, error) {
	const rootURI = "https://oauth2.googleapis.com/token"

	config, _ := initializers.LoadConfig(".")
	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("code", code)
	values.Add("client_id", config.GoogleClientID)
	values.Add("client_secret", config.GoogleClientSecret)
	values.Add("redirect_uri", config.GoogleOAuthRedirectUrl)

	query := values.Encode()

	req, err := http.NewRequest("POST", rootURI, bytes.NewBufferString(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not retrieve token")
	}

	var resBody bytes.Buffer
	_, err = io.Copy(&resBody, res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleOAuthTokenRes map[string]interface{}

	if err := json.Unmarshal(resBody.Bytes(), &GoogleOAuthTokenRes); err != nil {
		return nil, err
	}

	tokenBody := &GoogleOAuthToken{
		AccessToken: GoogleOAuthTokenRes["access_token"].(string),
		IDToken: GoogleOAuthTokenRes["id_token"].(string),
	}

	return tokenBody, nil
}

type GoogleUserResult struct {
	ID				string
	Email			string
	VerifiedEmail	bool
	Name			string
	GivenName		string
	FamilyName		string
	Photo			string
	Locale			string
}

func GetGoogleUser(access_token string, id_token string) (*GoogleUserResult, error) {
	rootUrl := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s", access_token)

	req, err := http.NewRequest("GET", rootUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", id_token))

	client := http.Client{
		Timeout: time.Second * 30,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not retrieve user")
	}

	var resBody bytes.Buffer
	_, err = io.Copy(&resBody, res.Body)
	if err != nil {
		return nil, err
	}

	var GoogleUserRes map[string]interface{}

	if err := json.Unmarshal(resBody.Bytes(), &GoogleUserRes); err != nil {
		return nil, err
	}

	userBody := &GoogleUserResult{
		ID:             GoogleUserRes["id"].(string),
		Email:          GoogleUserRes["email"].(string),
		VerifiedEmail: 	GoogleUserRes["verified_email"].(bool),
		Name:           GoogleUserRes["name"].(string),
		GivenName:   	GoogleUserRes["given_name"].(string),
		Photo:        	GoogleUserRes["picture"].(string),
		Locale:         GoogleUserRes["locale"].(string),
	}

	return userBody, nil
}