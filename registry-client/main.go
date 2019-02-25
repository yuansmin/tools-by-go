package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type AuthConfig struct {
	username string
	password string
}

var authConfig = &AuthConfig{"admin", "password"}
var (
	blobCon  int
	imageCon int
	schema   string
)

type registryToken struct {
	Token string `json:"token,"`
}

var rootCmd = &cobra.Command{
	Use:   "pull <image_name>",
	Short: "pull image like docker pull",
	Long:  ``,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return errors.New("requires at least one arg")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("start pull %s\n", args[1])
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&schema, "protocl", "p", "https", "one of [http, https]")
	rootCmd.PersistentFlags().IntVar(&blobCon, "blobCon", 10, "concurrence of download image layer")
	rootCmd.PersistentFlags().IntVar(&imageCon, "imageCon", 5, "concurrence of pull image")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func get_token(token_server string, scopes []string, service []string, auth_config *AuthConfig) (string, error) {
	tUrl, err := url.Parse(token_server)
	if err != nil {
		return "", err
	}

	values := url.Values{"service": service, "scope": scopes}
	tUrl.RawQuery = values.Encode()

	req := &http.Request{URL: tUrl, Method: "GET", Header: http.Header{}}
	// req.SetBasicAuth(auth_config.username, auth_config.password)

	client := get_https_client()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("get token resp: %s\n", string(data))
		return "", err
	}
	fmt.Println(string(data))

	token := &registryToken{}
	err = json.Unmarshal(data, token)
	if err != nil {
		return "", err
	}
	return token.Token, nil
}

func get_https_client() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}

}

func get_token_server(registry string) (string, string, error) {
	tUrl, err := url.Parse(registry)
	if err != nil {
		return "", "", err
	}

	tUrl.Path = "/v2/"
	client := get_https_client()
	req, _ := http.NewRequest("HEAD", tUrl.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	authHeader, _ := resp.Header["Www-Authenticate"]
	tmp := authHeader[0][len("bearer "):]
	tmps := strings.Split(tmp, ",")
	realm, service := "", ""
	for _, s := range tmps {
		if strings.HasPrefix(s, "realm") {
			realm = strings.TrimPrefix(s, "realm=")
			realm = strings.Trim(realm, "\"")
		} else if strings.HasPrefix(s, "service") {
			service = strings.TrimPrefix(s, "service=")
			service = strings.Trim(service, "\"")
		}
	}
	return realm, service, nil
}

func handle_auth(registry, repo_name string) string {
	realm, service, err := get_token_server(registry)
	if err != nil {
		panic(err)
	}

	scopes := []string{fmt.Sprintf("repository:%s:pull", repo_name)}

	token, err := get_token(realm, scopes, []string{service}, authConfig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("get token: \n%s\n", token)
	return token
}

type Manifest struct {
	Name      string              `json:"name,"`
	Tag       string              `json: "tag,"`
	FsLayers  []map[string]string `json: "fsLayers,"`
	History   []map[string]string `json: "history,"`
	Signature interface{}         `json: "signature,"`
}

func set_token_header(req *http.Request, token string) {
	req.Header = http.Header{
		"Authorization": []string{fmt.Sprintf("Bearer %s", token)},
	}
}

func get_manifest(base_url, tag, token string) (*Manifest, error) {
	client := get_https_client()
	url := fmt.Sprintf("%s/manifests/%s", base_url, tag)
	req, _ := http.NewRequest("GET", url, nil)
	set_token_header(req, token)
	resp, err := client.Do(req)
	data, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		fmt.Printf("get manifest err: %d, %s", resp.StatusCode, string(data))
	}
	if err != nil {
		return nil, err
	}
	mf := &Manifest{}
	err = json.Unmarshal(data, mf)
	if err != nil {
		fmt.Println(string(data))
		return nil, err
	}
	return mf, nil
}

func download_blob(base_url, b, token string, ch chan struct{}) {
	fmt.Printf("start pull blob %s\n", b[:20])
	client := get_https_client()
	url := fmt.Sprintf("%s/blobs/%s", base_url, b)
	req, _ := http.NewRequest("GET", url, nil)
	set_token_header(req, token)
	res, err := client.Do(req)
	data, _ := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("pull blob %s err: %s\n", b[:20], err)
	} else {
		fmt.Printf("%d pull blob %s %fKib \n", res.StatusCode, b[:20], float64(len(data))/1024.0)
	}
	<-ch
}

func get_blobs(base_url string, mf *Manifest, token string) {
	ch := make(chan struct{}, blobCon)
	for _, layer := range mf.FsLayers {
		blob, ok := layer["blobSum"]
		if ok {
			ch <- struct{}{}
			go download_blob(base_url, blob, token, ch)
		}
	}
}

func pull_image(registry, repo_name, tag string, ch chan struct{}) {
	base_url := fmt.Sprintf("%s/v2/%s", registry, repo_name)
	token := handle_auth(registry, repo_name)
	manifest, err := get_manifest(base_url, tag, token)
	if err != nil {
		fmt.Println("get manifest err: %s\n", err)
		return
	}

	get_blobs(base_url, manifest, token)
	ch <- struct{}{}
}
