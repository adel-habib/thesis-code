package main

import (
	"fmt"
	"github.com/adel-habib/thesis-code/services"
	"github.com/adel-habib/thesis-code/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

var oauth2Client services.OAuthService

func main() {

	oauth2Client = services.NewOAuth2ClientAuthorizationCodeFlow(
		"demo",
		"RwW2UlduwgLh5dqKu93RCDmUWlcWR6ae",
		"http://localhost:8082/auth/realms/thesis/protocol/openid-connect/auth",
		"http://localhost:8082/auth/realms/thesis/protocol/openid-connect/token",
		"http://localhost:8080/auth/callback",
	)

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	store := memstore.NewStore([]byte("secret"))
	store.Options(sessions.Options{MaxAge: 3600, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	r.Use(sessions.Sessions("sid", store))
	r.GET("/", indexHandler)
	r.GET("/login", loginHandler)
	r.GET("/oauth/callback", callbackHandler)
	authorized := r.Group("/")
	authorized.Use(AuthRequired())
	{
		authorized.GET("/protected", protectedHandler)
	}

	log.Fatal(r.Run(":8080"))
}

func indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", nil)
}

func loginHandler(c *gin.Context) {

	session := sessions.Default(c)
	state := utils.GenerateState()
	codeVerifier := utils.GenerateRandomString(32)
	codeChallenge := utils.GenerateCodeChallenge(codeVerifier)
	session.Set("code_verifier", codeVerifier)
	session.Set("state", state)
	err := session.Save()
	if err != nil {
		return
	}

	requestURI, err := oauth2Client.CreateAuthRequestURL(services.AuthRequestParams{
		State:        state,
		Scopes:       []string{"openid", "email", "profile"},
		RedirectURI:  "http://localhost:8080/oauth/callback",
		CustomParams: map[string]string{"code_challenge": codeChallenge, "code_challenge_method": "S256"},
	})
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.Redirect(http.StatusFound, requestURI)
}

func callbackHandler(c *gin.Context) {

	state := c.Query("state")
	session := sessions.Default(c)
	savedState := session.Get("state")

	if state != savedState {
		c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("invalid state"))
		return
	}
	code := c.Query("code")
	codeVerifier := session.Get("code_verifier").(string)
	token, err := oauth2Client.ExchangeCodeForToken(services.TokenExchangeParams{
		Code:         code,
		CodeVerifier: codeVerifier,
		RedirectURI:  "http://localhost:8080/oauth/callback",
	})
	if err != nil {
		session.Delete("state")
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	session.Set("token", token.AccessToken)
	session.Delete("state")
	err = session.Save()
	if err != nil {
		return
	}
	c.Redirect(http.StatusFound, "/protected")
}

func protectedHandler(c *gin.Context) {
	session := sessions.Default(c)
	token := session.Get("token")
	c.String(http.StatusOK, fmt.Sprintf("Hello, you're logged in with token: %s", token))
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		token := session.Get("token")
		if token == nil {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		c.Next()
	}
}
