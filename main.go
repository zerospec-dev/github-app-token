package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// sendはリクエストの結果をtargetにマップします。
func send(authorization *string, method string, url *string, target interface{}) error {

	// 送信
	request, err := http.NewRequest(method, *url, nil)
	if err != nil {
		return err
	}

	request.Header = map[string][]string{
		"Accept":               {"application/vnd.github+json"},
		"X-GitHub-Api-Version": {"2022-11-28"},
		"Authorization":        {fmt.Sprintf("Bearer %s", *authorization)},
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	if response.StatusCode/100 != 2 {
		return fmt.Errorf("request failed: %s", response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	// jsonにマッピングする
	err = json.Unmarshal(body, target)
	if err != nil {
		return err
	}

	return nil
}

type InstallationApiResponse struct {
	Id              int     `json:"id"`
	AccessTokensUrl *string `json:"access_tokens_url"`
}

type AccessTokenApiResponse struct {
	Token string `json:"token"`
}

type AccessToken struct {
	AppId            *string
	PemFilePath      *string
	OrganizationName *string
	RepositoryName   *string
}

func (args *AccessToken) CheckError(field *string, name string) {
	if field == nil || *field == "" {
		fmt.Fprintf(os.Stderr, "%s is not set\n", name)
		os.Exit(1)
	}
}

// getRepoNameはgithub上のリポジトリ名を返します。
func (args *AccessToken) getRepoName() string {
	return fmt.Sprintf("%s/%s", *args.OrganizationName, *args.RepositoryName)
}

// readPrivateKeyはファイルから秘密鍵を読み出して返します。
func (args *AccessToken) readPrivateKey() (*rsa.PrivateKey, error) {
	secret, err := ioutil.ReadFile(*args.PemFilePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(secret)
	privatekey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privatekey, nil
}

// getAuthorizationはAuthorizationヘッダに設定する文字列を作成して返します。
func (args *AccessToken) getAuthorization(privateKey *rsa.PrivateKey) (*string, error) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		jwt.MapClaims{
			"iss": args.AppId,
			"iat": jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
			"exp": jwt.NewNumericDate(time.Now().Add(+3 * time.Minute)),
		},
	)

	ss, err := token.SignedString(privateKey)
	if err != nil {
		return nil, err
	}

	return &ss, nil
}

// getAccessTokenEndpointはgithubからアクセストークンを取得するためのエンドポイントを返します。
func (args *AccessToken) getAccessTokenEndpoint(privateKey *rsa.PrivateKey) (*string, error) {
	// get installation api
	authorization, err := args.getAuthorization(privateKey)
	if err != nil {
		return nil, err
	}

	installationApiResponse := InstallationApiResponse{}
	installationApiUrl := fmt.Sprintf("https://api.github.com/repos/%s/installation", args.getRepoName())
	err = send(authorization, "GET", &installationApiUrl, &installationApiResponse)
	if err != nil {
		return nil, err
	}

	return installationApiResponse.AccessTokensUrl, nil
}

// getAccessTokenはgithubからアクセストークンを取得して返します。
func (args *AccessToken) getAccessToken(privateKey *rsa.PrivateKey, endpoint *string) (*string, error) {
	authorization, err := args.getAuthorization(privateKey)
	if err != nil {
		return nil, err
	}

	accessTokenApiResponse := AccessTokenApiResponse{}
	err = send(authorization, "POST", endpoint, &accessTokenApiResponse)
	if err != nil {
		return nil, err
	}

	return &accessTokenApiResponse.Token, nil
}

// Getはアクセストークンを取得して返します。
func (args *AccessToken) Get() (*string, error) {
	privateKey, err := args.readPrivateKey()
	if err != nil {
		return nil, err
	}

	endpoint, err := args.getAccessTokenEndpoint(privateKey)
	if err != nil {
		return nil, err
	}

	token, err := args.getAccessToken(privateKey, endpoint)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func main() {
	args := AccessToken{
		AppId:            flag.String("app", "", "AppID on Github Apps"),
		PemFilePath:      flag.String("pem", "", "path to pemfile of private key"),
		OrganizationName: flag.String("org", "", "owner or organization name of the repository"),
		RepositoryName:   flag.String("repo", "", "repository name"),
	}
	flag.Parse()

	args.CheckError(args.AppId, "app")
	args.CheckError(args.PemFilePath, "pem")
	args.CheckError(args.OrganizationName, "org")
	args.CheckError(args.RepositoryName, "repo")

	message, err := args.Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error occurred: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "%s\n", *message)
}
