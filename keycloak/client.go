package keycloak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	BaseURL     string
	AdminUser   string
	AdminPass   string
	httpClient  *http.Client
	AccessToken string
}

func NewClient(baseURL, adminUser, adminPass string) *Client {
	return &Client{
		BaseURL:    baseURL,
		AdminUser:  adminUser,
		AdminPass:  adminPass,
		httpClient: &http.Client{},
	}
}

func (client *Client) Authenticate() error {
	data := url.Values{}
	data.Set("client_id", "admin-cli")
	data.Set("username", client.AdminUser)
	data.Set("password", client.AdminPass)
	data.Set("grant_type", "password")

	req, err := http.NewRequest("POST", client.BaseURL+"/auth/realms/master/protocol/openid-connect/token", strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
	}

	var tokenResponse TokenResponse

	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return err
	}

	client.AccessToken = tokenResponse.AccessToken

	return nil
}

func (client *Client) CreateRealm(realm string) error {
	realmRep := RealmRepresentation{
		Realm:   realm,
		Enabled: true,
	}

	data, err := json.Marshal(realmRep)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", client.BaseURL+"/auth/admin/realms", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.AccessToken)
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected status code 201, got %d", resp.StatusCode)
	}

	return nil
}

func (client *Client) CreateClient(realm string, clientRep *ClientRepresentation) error {
	data, err := json.Marshal(clientRep)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", client.BaseURL+"/auth/admin/realms/"+realm+"/clients", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.AccessToken)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected status code 201, got %d", resp.StatusCode)
	}

	return nil
}

func (client *Client) CreateGroup(realm string, groupRep *GroupRepresentation) error {
	data, err := json.Marshal(groupRep)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", client.BaseURL+"/auth/admin/realms/"+realm+"/groups", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.AccessToken)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected status code 201, got %d", resp.StatusCode)
	}

	return nil
}

func (client *Client) CreateUser(realm string, userRep *UserRepresentation) error {
	data, err := json.Marshal(userRep)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", client.BaseURL+"/auth/admin/realms/"+realm+"/users", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.AccessToken)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected status code 201, got %d", resp.StatusCode)
	}

	return nil
}

func (client *Client) CreateUserWithCredentials(realm string, userRep *UserRepresentation, credentials *CredentialsRepresentation) error {
	userRep.Credentials = []*CredentialsRepresentation{credentials}

	data, err := json.Marshal(userRep)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", client.BaseURL+"/auth/admin/realms/"+realm+"/users", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.AccessToken)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected status code 201, got %d", resp.StatusCode)
	}

	return nil
}

func (client *Client) AddUserToGroup(realm, userID, groupID string) error {
	req, err := http.NewRequest("PUT", client.BaseURL+"/auth/admin/realms/"+realm+"/users/"+userID+"/groups/"+groupID, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+client.AccessToken)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("expected status code 204, got %d", resp.StatusCode)
	}

	return nil
}

type RoleRepresentation struct {
	Name string `json:"name"`
}

func (client *Client) AddRoleMapping(realm, userID string, role *RoleRepresentation) error {
	data, err := json.Marshal([]*RoleRepresentation{role})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", client.BaseURL+"/auth/admin/realms/"+realm+"/users/"+userID+"/role-mappings/realm", bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.AccessToken)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("expected status code 204, got %d", resp.StatusCode)
	}

	return nil
}

func (client *Client) EnablePKCEAndRequirePAR(realm string, clientRep *ClientRepresentation) error {
	clientRep.Attributes = map[string]string{
		"pkce.code.challenge.method": "S256",
		"oauth2.require.par":         "true",
	}

	data, err := json.Marshal(clientRep)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", client.BaseURL+"/auth/admin/realms/"+realm+"/clients/"+clientRep.ClientID, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.AccessToken)

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("expected status code 204, got %d", resp.StatusCode)
	}

	return nil
}
