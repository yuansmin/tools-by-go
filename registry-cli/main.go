package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	SCHEMA1_MEDIA_TYPE_MANIFEST = "application/vnd.docker.distribution.manifest.v1+json"
	SCHEMA2_MEDIA_TYPE_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
	NAME                        = "registry-cli"
	dockerCFGConfig             = ".docker/config.json"
)

var (
	registryAddr string // registry addr
	schema       string
	user         string // <name>:<pwd>
	verbose      bool   // output verbose if true
	namespace    string

	registry *Registry
	auth     *AuthConfig
)

func init() {
	rootCmd.AddCommand(nsCmd)
	nsCmd.AddCommand(nsListCmd)
	rootCmd.AddCommand(repoCmd)
	repoCmd.AddCommand(repoListCmd)
	rootCmd.AddCommand(tagCmd)
	tagCmd.AddCommand(tagListCmd)
	tagCmd.AddCommand(tagMFCmd)
	tagCmd.AddCommand(tagDelCmd)
	tagCmd.AddCommand(tagCPCmd)

	rootCmd.PersistentFlags().StringVarP(&registryAddr, "registry-addr", "r", "", "registry addr (required)")
	rootCmd.MarkPersistentFlagRequired("registryAddr")
	rootCmd.PersistentFlags().StringVarP(&user, "user", "u", "", "user info, <name>:<pwd>")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "output verbose info")

	repoListCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "filter repo by namespace")
	tagMFCmd.Flags().StringVarP(&schema, "schema", "s", "v2", "manifest schema, [v1, v2] default v2")
}

var rootCmd = &cobra.Command{
	Use:   NAME,
	Short: "a simple registry cmd tools",
	Long:  ``,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
		} else {
			log.SetLevel(log.InfoLevel)
		}
		registry = getRegistry()
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Usage()
	},
}

var nsCmd = &cobra.Command{
	Use:   "ns",
	Short: "namespace",
	Long:  `namespace`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Usage()
	},
}

var nsListCmd = &cobra.Command{
	Use:   "list",
	Short: "list namespaces",
	Long:  `list namespaces`,
	Run: func(cmd *cobra.Command, args []string) {
		listNamespaces(registry)
	},
}

var repoCmd = &cobra.Command{
	Use:   "repo",
	Short: "repo",
	Long:  `repo`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Usage()
	},
}

var repoListCmd = &cobra.Command{
	Use:   "list",
	Short: "list all repositories",
	Long:  `list all repositories`,
	Run: func(cmd *cobra.Command, args []string) {
		listRepo(registry, namespace)
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
	Short: "list repo tags",
	Long:  `list repo tags`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("requires one arg, repo name")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
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
		cpRepoTag(registry, args[0], args[1])
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errorf("%s", err)
		os.Exit(1)
	}
}

func getAuthConfig() *AuthConfig {
	var name, pwd string
	if user != "" {
		cp := strings.SplitN(user, ":", 2)
		name = cp[0]
		if len(cp) == 2 {
			pwd = cp[1]
		}
	} else {
		name, pwd = getAuthFromDockerCFG(registryAddr)
		if name != "" && pwd != "" {
			log.Debugf("get registry account from ~/.docker/config")
		}
	}

	return &AuthConfig{name, pwd}
}

func getAuthFromDockerCFG(addr string) (name, pwd string) {
	u, err := osuser.Current()
	if err != nil {
		log.Debug(err)
		return
	}

	aPath := filepath.Join(u.HomeDir, dockerCFGConfig)
	raw, err := ioutil.ReadFile(aPath)
	if err != nil {
		log.Debugf("get registry auth info from %s err: %s", dockerCFGConfig, err)
		return
	}
	type auth struct {
		Auth string `json:"auth"`
	}

	type AuthConf struct {
		Auths map[string]auth `json:"auths"`
	}
	conf := &AuthConf{}
	err = json.Unmarshal(raw, conf)
	if err != nil {
		log.Debugf("unmarshal %s err: %s", dockerCFGConfig, err)
		return
	}
	c, ok := conf.Auths[addr]
	if !ok {
		return
	}
	if c.Auth == "" {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(c.Auth)
	if err != nil {
		log.Debugf("decode error: %s", err)
		return
	}
	cp := strings.SplitN(string(decoded), ":", 2)
	name = cp[0]
	if len(cp) == 2 {
		pwd = cp[1]
	}
	return
}

func getRegistry() *Registry {
	var err error
	auth := getAuthConfig()
	registry, err = NewRegistry(registryAddr, auth)
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

func filterRepoByNamespace(repos []string, namespace string) []string {
	prefix := fmt.Sprintf("%s/", namespace)
	var r []string
	for _, name := range repos {
		if strings.HasPrefix(name, prefix) {
			r = append(r, name)
		}
	}
	return r
}

func listNamespaces(r *Registry) {
	ns, err := r.ListNamespaces()
	if err != nil {
		log.Errorf("list repo err: %v", err)
	}
	printList(ns)
}

func listRepo(r *Registry, namespace string) {

	repos, err := r.ListRepoes()
	if err != nil {
		log.Errorf("list repo err: %v", err)
	}
	if namespace != "" {
		repos = filterRepoByNamespace(repos, namespace)
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
	name, tag := cp[0], cp[1]
	err := r.DeleteRepoTag(name, tag)
	if err != nil {
		log.Errorf("delete tag err: %v", err)
		os.Exit(1)
	}
	log.Infof("delete tag %s success", repoName)
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

// do registry http request, handle auth token, get new or cache token
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
	log.Debugf("do request %s %s", req.Method, req.URL.Path)
	res, err := r.httpClient.Do(req)
	return res, err
}

func (r *Registry) GetToken(scope string) (token string, err error) {
	if r.authServerAddress == "" {
		if server, err := r.getAuthServer(); err != nil {
			return "", err
		} else {
			log.Debugf("get auth server address: %s\n", server)
			r.authServerAddress = server
		}
	}

	req, _ := http.NewRequest("GET", r.authServerAddress, nil)
	req.SetBasicAuth(r.authConfig.username, r.authConfig.password)
	reqParams := req.URL.Query()
	reqParams.Add("scope", scope)
	req.URL.RawQuery = reqParams.Encode()

	log.Debugf("do request %s %s", req.Method, req.URL.String())
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
	var data struct {
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(res.Body)
	if err = decoder.Decode(&data); err != nil {
		return
	}
	token = data.Token
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
	if !isSuccessCode(res.StatusCode) && res.StatusCode != 401 {
		fmt.Println("yes")
		// data, err := ioutil.ReadAll(res.Body)
		// msg := fmt.Sprintf("%d %s", res.StatusCode, string(data))
		// if err != nil {
		// 	msg = fmt.Sprintf("%s%s", msg, err)
		// }
		// err = fmt.Errorf(msg)

		_, err = checkAndReadResponse(res)
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

func checkAndReadResponse(res *http.Response) ([]byte, error) {
	data, err := ioutil.ReadAll(res.Body)
	if isSuccessCode(res.StatusCode) {
		return data, err
	}

	var msg string
	if err != nil {
		msg = fmt.Sprintf("%d %s", res.StatusCode, err)
	} else {
		msg = fmt.Sprintf("%d %s", res.StatusCode, string(data))
	}
	return data, fmt.Errorf(msg)
}

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

	raw, err := checkAndReadResponse(res)
	if err != nil {
		return nil, err
	}

	data := make(map[string][]string)
	err = json.Unmarshal(raw, &data)
	if err != nil {
		return nil, err
	}

	repoes = data["repositories"]
	sort.Strings(repoes)
	return
}

func getNamespacesFromRepoes(repos []string) []string {
	ns_map := make(map[string]string)
	for _, r := range repos {
		part := strings.SplitN(r, "/", 2)
		if len(part) == 2 {
			ns_map[part[0]] = ""
		} else {
			// empty namespace, "library" in docker hub
			ns_map[""] = ""
		}
	}

	var ns []string
	for k, _ := range ns_map {
		ns = append(ns, k)
	}
	return ns
}

func (r *Registry) ListNamespaces() ([]string, error) {
	repos, err := r.ListRepoes()
	if err != nil {
		return nil, err
	}
	ns := getNamespacesFromRepoes(repos)
	sort.Strings(ns)
	return ns, nil
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

	raw, err := checkAndReadResponse(res)
	if err != nil {
		return nil, err
	}

	data := struct {
		Tags []string `json:"tags"`
	}{}
	err = json.Unmarshal(raw, &data)
	if err != nil {
		return nil, err
	}

	tags = data.Tags
	sort.Strings(tags)
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

	raw, err := checkAndReadResponse(res)
	if err != nil {
		return "", "", err
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

	_, err = checkAndReadResponse(res)
	if err != nil {
		return "", err
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

	_, err = checkAndReadResponse(res)
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

	_, err = checkAndReadResponse(res)
	if err != nil {
		return "", err
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
	return r, nil
}

func isSuccessCode(code int) bool {
	if code >= 200 && code < 300 {
		return true
	}
	return false
}

func printList(array []string) {
	fmt.Println()
	for _, v := range array {
		fmt.Printf("%v\n", v)
	}
}
