package services

import (
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type OAuth2Client struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	ParUrl       string
	RedirectURI  string
	HttpClient   *http.Client
}

func NewOAuth2Client(clientID, clientSecret, authURL, tokenURL, redirectURI string) *OAuth2Client {
	return &OAuth2Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthURL:      authURL,
		TokenURL:     tokenURL,
		RedirectURI:  redirectURI,
		HttpClient: &http.Client{
			Timeout: time.Second * 2,
		},
	}
}

func (c *OAuth2Client) RedirectURL() string {
	return c.RedirectURI
}

func (c *OAuth2Client) exchangeToken(values url.Values) (*oauth2.Token, error) {
	resp, err := c.HttpClient.PostForm(c.TokenURL, values)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, errors.New("failed to exchange token")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var token oauth2.Token
	err = json.Unmarshal(body, &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

type AuthRequestParams struct {
	State        string
	Scopes       []string
	RedirectURI  string
	CustomParams map[string]string
}

type TokenExchangeParams struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
	CustomParams map[string]string
}

type OAuthService interface {
	CreateAuthRequestURL(params AuthRequestParams) (string, error)
	ExchangeCodeForToken(params TokenExchangeParams) (*oauth2.Token, error)
}
