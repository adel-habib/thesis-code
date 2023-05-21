package services

import (
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"strings"
)

type OAuth2ClientPushedAuthorizationRequestWithPKCE struct {
	*OAuth2Client
}

func NewOAuth2ClientPushedAuthorizationRequestWithPKCE(clientID, clientSecret, authURL, tokenURL, parURL, redirectURI string) *OAuth2ClientPushedAuthorizationRequestWithPKCE {
	client := NewOAuth2Client(clientID, clientSecret, authURL, tokenURL, redirectURI)
	client.ParUrl = parURL
	return &OAuth2ClientPushedAuthorizationRequestWithPKCE{
		OAuth2Client: client,
	}
}

func (c *OAuth2ClientPushedAuthorizationRequestWithPKCE) CreateAuthRequestURL(params AuthRequestParams) (string, error) {
	data := url.Values{
		"client_id":     {c.ClientID},
		"redirect_uri":  {c.RedirectURI},
		"scope":         {strings.Join(params.Scopes, " ")},
		"response_type": {"code"},
		"state":         {params.State},
	}
	for k, v := range params.CustomParams {
		data.Set(k, v)
	}

	req, err := http.NewRequest(http.MethodPost, c.ParUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", errors.New("pushed authorization request failed")
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	requestURI, ok := result["request_uri"].(string)
	if !ok {
		return "", errors.New("invalid request URI")
	}
	return requestURI, nil
}

func (c *OAuth2ClientPushedAuthorizationRequestWithPKCE) ExchangeCodeForToken(params TokenExchangeParams) (*oauth2.Token, error) {
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", params.Code)
	values.Set("redirect_uri", params.RedirectURI)
	values.Set("client_id", c.ClientID)
	values.Set("client_secret", c.ClientSecret)
	values.Set("code_verifier", params.CodeVerifier)
	for k, v := range params.CustomParams {
		values.Set(k, v)
	}
	return c.exchangeToken(values)
}
