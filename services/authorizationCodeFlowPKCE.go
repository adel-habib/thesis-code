package services

import (
	"github.com/adel-habib/thesis-code/utils"
	"golang.org/x/oauth2"
	"net/url"
	"strings"
)

type OAuth2ClientAuthorizationCodeFlowWithPKCE struct {
	*OAuth2Client
}

func NewOAuth2ClientAuthorizationCodeFlowWithPKCE(clientID, clientSecret, authURL, tokenURL, redirectURI string) *OAuth2ClientAuthorizationCodeFlowWithPKCE {
	return &OAuth2ClientAuthorizationCodeFlowWithPKCE{
		OAuth2Client: NewOAuth2Client(clientID, clientSecret, authURL, tokenURL, redirectURI),
	}
}

func (c *OAuth2ClientAuthorizationCodeFlowWithPKCE) CreateAuthRequestURL(params AuthRequestParams) (string, error) {
	codeVerifier := utils.GenerateRandomString(8)
	codeChallenge := utils.GenerateCodeChallenge(codeVerifier)

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", c.ClientID)
	values.Set("redirect_uri", params.RedirectURI)
	values.Set("scope", strings.Join(params.Scopes, " "))
	values.Set("state", params.State)
	values.Set("code_challenge", codeChallenge)
	values.Set("code_challenge_method", "S256")

	for k, v := range params.CustomParams {
		values.Set(k, v)
	}

	return c.AuthURL + "?" + values.Encode(), nil
}

func (c *OAuth2ClientAuthorizationCodeFlowWithPKCE) ExchangeCodeForToken(params TokenExchangeParams) (*oauth2.Token, error) {
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
