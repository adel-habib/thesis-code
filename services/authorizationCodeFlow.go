package services

import (
	"golang.org/x/oauth2"
	"net/url"
	"strings"
)

type OAuth2ClientAuthorizationCodeFlow struct {
	*OAuth2Client
}

func NewOAuth2ClientAuthorizationCodeFlow(clientID, clientSecret, authURL, tokenURL, redirectURI string) *OAuth2ClientAuthorizationCodeFlow {
	return &OAuth2ClientAuthorizationCodeFlow{
		OAuth2Client: NewOAuth2Client(clientID, clientSecret, authURL, tokenURL, redirectURI),
	}
}

func (c *OAuth2ClientAuthorizationCodeFlow) CreateAuthRequestURL(params AuthRequestParams) (string, error) {
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", c.ClientID)
	values.Set("redirect_uri", params.RedirectURI)
	values.Set("scope", strings.Join(params.Scopes, " "))
	values.Set("state", params.State)

	for k, v := range params.CustomParams {
		values.Set(k, v)
	}

	return c.AuthURL + "?" + values.Encode(), nil
}

func (c *OAuth2ClientAuthorizationCodeFlow) ExchangeCodeForToken(params TokenExchangeParams) (*oauth2.Token, error) {
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", params.Code)
	values.Set("redirect_uri", params.RedirectURI)
	values.Set("client_id", c.ClientID)
	values.Set("client_secret", c.ClientSecret)

	for k, v := range params.CustomParams {
		values.Set(k, v)
	}

	return c.exchangeToken(values)
}
