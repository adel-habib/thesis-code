package keycloak

type RealmRepresentation struct {
	Realm   string `json:"realm"`
	Enabled bool   `json:"enabled"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

type ClientRepresentation struct {
	ClientID                  string            `json:"clientId,omitempty"`
	Name                      string            `json:"name"`
	RootURL                   string            `json:"rootUrl"`
	Public                    bool              `json:"publicClient"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	Attributes                map[string]string `json:"attributes,omitempty"`
}

type GroupRepresentation struct {
	Name string `json:"name"`
}

type UserRepresentation struct {
	Username    string                       `json:"username"`
	Email       string                       `json:"email"`
	Enabled     bool                         `json:"enabled"`
	Credentials []*CredentialsRepresentation `json:"credentials,omitempty"`
}

type CredentialsRepresentation struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}
