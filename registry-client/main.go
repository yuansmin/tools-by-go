package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	SCHEMA1_MEDIA_TYPE_MANIFEST = "application/vnd.docker.distribution.manifest.v1+json"
	SCHEMA2_MEDIA_TYPE_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
	NAME                        = "Zeus"
)

var (
	showVersion = true
	addr        string // registry addr
	schema      string

	registry *Registry

	auth = &AuthConfig{"admin", "changeme"}
)

func init() {
	log.SetLevel(logrus.DebugLevel)
	rootCmd.AddCommand(repoCmd)
	repoCmd.AddCommand(repoListCmd)
	rootCmd.AddCommand(tagCmd)
	tagCmd.AddCommand(tagListCmd)
	tagCmd.AddCommand(tagMFCmd)
	tagCmd.AddCommand(tagDelCmd)
	tagCmd.AddCommand(tagCPCmd)
	// getCmd.AddCommand(repoCmd)
	rootCmd.PersistentFlags().StringVarP(&addr, "addr", "a", "", "registry addr (required)")
	rootCmd.MarkPersistentFlagRequired("addr")

	tagMFCmd.Flags().StringVarP(&schema, "schema", "s", "v2", "manifest schema, [v1, v2] default v2")
	// 	rootCmd.PersistentFlags().BoolVarP(&https, "https", "", true, "whether use https")
	// 	rootCmd.PersistentFlags().BoolVarP(&verify, "verify", "k", false, "whether verify https cert")
	// 	rootCmd.PersistentFlags().IntVar(&blobCon, "blobCon", 3, "concurrence of download image layer")
	// 	rootCmd.PersistentFlags().IntVarP(&imageCon, "imageCon", "i", 5, "concurrence of pull image")
	// 	rootCmd.PersistentFlags().IntVarP(&times, "times", "t", 1, "run test times")
}

var rootCmd = &cobra.Command{
	Use:   NAME,
	Short: "a simple registry cmd tools",
	Long:  ``,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return errors.New("requires at least one arg")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		if showVersion {
			fmt.Printf("%s 0.1.0\n", NAME)
			return
		}
		cmd.Usage()
	},
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "get",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Usage()
	},
}

var repoCmd = &cobra.Command{
	Use:   "repo",
	Short: "repo",
	Long:  `repo`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("hello world~")
	},
}

var repoListCmd = &cobra.Command{
	Use:   "list",
	Short: "list",
	Long:  `list all repositories`,
	Run: func(cmd *cobra.Command, args []string) {
		registry := getRegistry()
		listRepo(registry)
	},
}

var tagCmd = &cobra.Command{
	Use:   "tag",
	Short: "tag",
	Long:  `tag`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Usage()
	},
}

var tagListCmd = &cobra.Command{
	Use:   "list",
	Short: "list",
	Long:  `list repo tags`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires one arg, repo name")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		registry := getRegistry()
		listRepoTag(registry, args[0])
	},
}

var tagMFCmd = &cobra.Command{
	Use:   "mf <repo:tag>",
	Short: "get tag manifest",
	Long:  `print tag manifest`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires one arg, repo name")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		if schema != "v2" && schema != "v1" {
			log.Warnf("Invalid schema %s, use default v2", schema)
			schema = "v1"
		}
		registry := getRegistry()
		getTagManifest(registry, args[0], schema)
	},
}

var tagDelCmd = &cobra.Command{
	Use:   "del <repo:tag>",
	Short: "del tag",
	Long:  `delete tag`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires one arg, repo name")
		}
		if len(strings.SplitN(args[0], ":", 2)) != 2 {
			return errors.New("please specify repo tag like <repo-name>:<tag>")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		registry := getRegistry()
		deleteRepoTag(registry, args[0])
	},
}

var tagCPCmd = &cobra.Command{
	Use:   "cp <source-repo:tag> <target-repo:tag>",
	Short: "cp tag",
	Long:  `cp <source-repo:tag> <target-repo:tag>`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 2 {
			return errors.New("requires two args, source repo name and target repo name")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		registry := getRegistry()
		cpRepoTag(registry, args[0], args[1])
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// auth := &AuthConfig{"admin", "changeme"}
	// r, err := NewRegistry("10.6.170.191", auth)
	// if err != nil {
	// 	panic(err)
	// }
	// data, err := r.ListRepoes()
	// data, err := r.listRepoTags("kube-system/dce-busybox")
	// data, err := r.GetTagManifest("kube-system/dce-busybox", "1.30.1", "v2")
	// if err != nil {
	// 	fmt.Printf("%v\n", err)
	// }
	// fmt.Printf("%s\n", data)
	// printList(data)
}

func getRegistry() *Registry {
	var err error
	registry, err = NewRegistry(addr, auth)
	if err != nil {
		log.Errorf("init registry err: %v", err)
		os.Exit(0)
	}
	return registry
}

// parse <repo-name>:<tag>
func parseImageName(name string) (repoName, tag string) {
	cp := strings.SplitN(name, ":", 2)
	repoName = cp[0]
	tag = "latest"
	if len(cp) == 2 {
		tag = cp[1]
	}
	return
}

func listRepo(r *Registry) {

	repos, err := r.ListRepoes()
	if err != nil {
		log.Errorf("list repo err: %v", err)
	}
	printList(repos)
}

func listRepoTag(r *Registry, repoName string) {
	tags, err := r.ListRepoTags(repoName)
	if err != nil {
		log.Errorf("list repo tag err: %v", err)
	}
	printList(tags)
}

func getTagManifest(r *Registry, repoName, schema string) {
	tag := "latest"
	cp := strings.Split(repoName, ":")
	if len(cp) == 2 {
		repoName, tag = cp[0], cp[1]
	}
	digest, mf, err := r.GetTagManifest(repoName, tag, schema)
	if err != nil {
		log.Errorf("get tag manifest err: %v", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n%s\n", digest, mf)
}

func deleteRepoTag(r *Registry, repoName string) {
	cp := strings.SplitN(repoName, ":", 2)
	repoName, tag := cp[0], cp[1]
	err := r.DeleteRepoTag(repoName, tag)
	if err != nil {
		log.Errorf("delete tag err: %v", err)
		os.Exit(1)
	}
}

// source, target are image name with tag. eg: dao-2048:0.1
func cpRepoTag(r *Registry, source, target string) {
	sRepoName, sTag := parseImageName(source)
	_, mf, err := r.GetTagManifest(sRepoName, sTag, "v2")
	if err != nil {
		log.Errorf("get %s manifest err: %s", source, err)
		os.Exit(1)
	}

	repoName, tag := parseImageName(target)
	digest, err := r.CreateRepoTag(repoName, tag, mf)
	if err != nil {
		log.Errorf("cp %s err: %s", source, err)
		os.Exit(1)
	}

	log.Infof("cp %s to %s success, new tag digest: %s", source, target, digest)
}

type AuthConfig struct {
	username string
	password string
}

type Registry struct {
	// http://192.168.1.30:8000
	Address    string
	authConfig *AuthConfig
	httpClient *http.Client
	// a cache, [scope, token]
	scopeToken [2]string
	// http://192.168.1.4:8080/registry/token?service=xxx
	authServerAddress string
}

// do registry http request, handle auth token, get new or cache token, refresh token when expired
func (r *Registry) do(req *http.Request, scope string) (*http.Response, error) {
	token := r.scopeToken[1]
	if scope != r.scopeToken[0] {
		var err error
		token, err = r.GetToken(scope)
		if err != nil {
			return nil, err
		}
	}
	setToken(req, token)
	res, err := r.httpClient.Do(req)
	return res, err
}

func (r *Registry) GetToken(scope string) (token string, err error) {
	if r.authServerAddress == "" {
		if server, err := r.getAuthServer(); err != nil {
			return "", err
		} else {
			fmt.Printf("get auth server address: %s\n", server)
			r.authServerAddress = server
		}
	}

	// todo: auth
	req, _ := http.NewRequest("GET", r.authServerAddress, nil)
	req.SetBasicAuth(r.authConfig.username, r.authConfig.password)
	reqParams := req.URL.Query()
	reqParams.Add("scope", scope)
	req.URL.RawQuery = reqParams.Encode()

	log.Debugf("request %s %s", req.Method, req.URL.String())
	res, err := r.httpClient.Do(req)
	if err != nil {
		return
	}

	defer res.Body.Close()
	if res.StatusCode == 401 {
		return "", fmt.Errorf("401 authentication failed, please check your username & password")
	} else if !isSuccessCode(res.StatusCode) {
		return "", fmt.Errorf("get token err: %d", res.StatusCode)
	}
	var data map[string]string
	decoder := json.NewDecoder(res.Body)
	if err = decoder.Decode(&data); err != nil {
		return
	}
	token = data["token"]
	return
}

func (r *Registry) getAuthServer() (server string, err error) {
	url := fmt.Sprintf("%s/v2/", r.Address)
	req, _ := http.NewRequest("GET", url, nil)
	res, err := r.httpClient.Do(req)
	if err != nil {
		return
	}

	defer res.Body.Close()
	// todo: optimize
	if res.StatusCode >= 500 {
		data, err := ioutil.ReadAll(res.Body)
		msg := fmt.Sprintf("%d %s", res.StatusCode, string(data))
		if err != nil {
			msg = fmt.Sprintf("%s%s", msg, err)
		}
		err = fmt.Errorf(msg)
		return "", err
	}
	raw := res.Header.Get("Www-Authenticate")
	server, err = parseBeararAuth(raw)
	return
}

func parseBeararAuth(raw string) (string, error) {
	// Bearer realm="https://daohub-auth.daocloud.io/auth",service="daocloud.io",scope="registry:catalog:*"
	parts := strings.Split(strings.TrimSpace(strings.TrimLeft(raw, "Bearer")), ",")
	m := make(map[string]string)
	for _, p := range parts {
		pp := strings.SplitN(p, "=", 2)
		if len(pp) == 2 {
			m[pp[0]] = strings.ReplaceAll(pp[1], "\"", "")
		}
	}
	fmt.Printf("parts: %s\nm: %v\n", parts, m)
	var realm string
	if _, ok := m["realm"]; !ok {
		return "", fmt.Errorf("bad bearer header, no realm: %s", raw)
	}
	realm = m["realm"]
	if _, ok := m["service"]; ok {
		realm = fmt.Sprintf("%s?service=%s", realm, m["service"])
	}
	return realm, nil
}

// func generateResponseErr(res *http.Response) error {
// 	return fmt.Errorf("%d %s", res.StatusCode, res.body)
// }

func setToken(req *http.Request, token string) {
	value := fmt.Sprintf("Bearer %s", token)
	req.Header.Set("Authorization", value)
}

func (r *Registry) ListRepoes() (repoes []string, err error) {
	url := fmt.Sprintf("%s/v2/_catalog", r.Address)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	scope := "registry:catalog:*"
	res, err := r.do(req, scope)
	if err != nil {
		return
	}

	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	if !isSuccessCode(res.StatusCode) {
		return nil, fmt.Errorf("%d %s", res.StatusCode, raw)
	}

	data := make(map[string][]string)
	err = json.Unmarshal(raw, &data)
	if err != nil {
		return nil, err
	}

	repoes = data["repositories"]
	return
}

func (r *Registry) ListRepoTags(repo_name string) (tags []string, err error) {
	url := fmt.Sprintf("%s/v2/%s/tags/list", r.Address, repo_name)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	scope := fmt.Sprintf("repository:%s:pull", repo_name)
	res, err := r.do(req, scope)
	if err != nil {
		return
	}

	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	if !isSuccessCode(res.StatusCode) {
		return nil, fmt.Errorf("%d %s", res.StatusCode, raw)
	}

	// data := make(map[string][]string)
	data := struct {
		Tags []string `json:"tags"`
	}{}
	err = json.Unmarshal(raw, &data)
	if err != nil {
		return nil, err
	}

	tags = data.Tags
	return
}

// schema: manifest schema type [v1, v2], default: v2
func (r *Registry) GetTagManifest(repo_name, tag, schema string) (digest, manifest string, err error) {
	if schema == "" {
		schema = "v2"
	}
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", r.Address, repo_name, tag)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	accept := SCHEMA2_MEDIA_TYPE_MANIFEST
	if schema != "v2" {
		accept = SCHEMA1_MEDIA_TYPE_MANIFEST
	}
	req.Header.Set("accept", accept)
	scope := fmt.Sprintf("repository:%s:pull", repo_name)
	res, err := r.do(req, scope)
	if err != nil {
		return
	}

	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	if !isSuccessCode(res.StatusCode) {
		return "", "", fmt.Errorf("%d %s", res.StatusCode, raw)
	}
	manifest = string(raw)
	digest = res.Header.Get("Docker-Content-Digest")
	return
}

func (r *Registry) GetTagDigest(repoName, tag string) (digest string, err error) {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", r.Address, repoName, tag)
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("accept", SCHEMA2_MEDIA_TYPE_MANIFEST)
	scope := fmt.Sprintf("repository:%s:pull", repoName)
	res, err := r.do(req, scope)
	if err != nil {
		return
	}

	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	if !isSuccessCode(res.StatusCode) {
		return "", fmt.Errorf("%d %s", res.StatusCode, raw)
	}

	digest = res.Header.Get("Docker-Content-Digest")
	log.Debugf("get %s:%s digest: %s", repoName, tag, digest)
	return
}

func (r *Registry) DeleteRepoTag(repoName, tag string) (err error) {
	digest, err := r.GetTagDigest(repoName, tag)
	if err != nil {
		return fmt.Errorf("get tag digest err: %s", err)
	}
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", r.Address, repoName, digest)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return
	}
	scope := fmt.Sprintf("repository:%s:*", repoName)
	res, err := r.do(req, scope)
	if err != nil {
		return
	}

	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	if !isSuccessCode(res.StatusCode) {
		return fmt.Errorf("%d %s", res.StatusCode, raw)
	}
	return
}

// mf: image manifest string
// return new tag manifest if create succeed
func (r *Registry) CreateRepoTag(repoName, tag, mf string) (digest string, err error) {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", r.Address, repoName, tag)
	req, err := http.NewRequest("PUT", url, bytes.NewReader([]byte(mf)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", SCHEMA2_MEDIA_TYPE_MANIFEST)
	scope := fmt.Sprintf("repository:%s:push", repoName)
	res, err := r.do(req, scope)
	if err != nil {
		return
	}

	defer res.Body.Close()

	raw, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	if !isSuccessCode(res.StatusCode) {
		return "", fmt.Errorf("%d %s", res.StatusCode, raw)
	}
	digest = res.Header.Get("Docker-Content-Digest")
	return
}

// address: <host>:<port>
// detect registry http schema
func (r *Registry) DetectSchema(address string) (schema string, err error) {
	schemas := []string{"https", "http"}
	for _, s := range schemas {
		url := fmt.Sprintf("%s://%s/v2/", s, address)
		var res *http.Response
		client := http.Client{}
		if s == "https" {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client = http.Client{
				Transport: tr,
				Timeout:   10 * time.Second,
			}
		}
		req, _ := http.NewRequest("GET", url, nil)
		res, err = client.Do(req)
		if err != nil {
			break
		}
		if res.StatusCode == 401 || isSuccessCode(res.StatusCode) {
			schema = s
			return
		}
	}
	return
}

// addresss: <host>:<port>
func NewRegistry(address string, auth *AuthConfig) (*Registry, error) {

	r := &Registry{authConfig: auth}
	schema, err := r.DetectSchema(address)
	if err != nil {
		return nil, err
	}

	log.Debugf("detect registry schema: %s", schema)
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if schema == "https" {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient.Transport = tr
	}
	r.httpClient = httpClient
	address = fmt.Sprintf("%s://%s", schema, address)
	r.Address = address
	fmt.Printf("r %v\n", r)
	return r, nil
}

func isSuccessCode(code int) bool {
	if code >= 200 && code < 300 {
		return true
	}
	return false
}

func printList(array []string) {
	for _, v := range array {
		fmt.Printf("%v\n", v)
	}
}
