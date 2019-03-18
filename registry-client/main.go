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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	ImageDefaultTagName = "latest"
)

type AuthConfig struct {
	username string
	password string
}

var authConfig = &AuthConfig{"admin", "password"}
var (
	blobCon  int
	imageCon int
	https    bool
	verify   bool
	times    int
)

type registryToken struct {
	Token string `json:"token,"`
}

type Result struct {
	Cost   int64
	Size   int // unit
	Digest string
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
		start_test(args[1], imageCon, blobCon, times, https, verify)
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&https, "https", "", true, "whether use https")
	rootCmd.PersistentFlags().BoolVarP(&verify, "verify", "k", false, "whether verify https cert")
	rootCmd.PersistentFlags().IntVar(&blobCon, "blobCon", 3, "concurrence of download image layer")
	rootCmd.PersistentFlags().IntVarP(&imageCon, "imageCon", "i", 5, "concurrence of pull image")
	rootCmd.PersistentFlags().IntVarP(&times, "times", "t", 1, "run test times")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var Unit = map[int]string{
	0: "B",
	1: "KiB",
	2: "MiB",
	3: "GiB",
}
var baseUnit float64 = 1024

func getHumanreadableUnit(size int) string {
	var unitCode int = -1
	var num float64 = float64(size)
	unit := num
	for {
		if num < 1 {
			break
		}
		unit = num
		num = num / baseUnit
		unitCode++
	}

	return fmt.Sprintf("%.2f%s", unit, Unit[unitCode])
}

func get_token(token_server string, scopes []string, service []string, auth_config *AuthConfig, client *http.Client) (string, error) {
	tUrl, err := url.Parse(token_server)
	if err != nil {
		return "", err
	}

	values := url.Values{"service": service, "scope": scopes}
	tUrl.RawQuery = values.Encode()

	req := &http.Request{URL: tUrl, Method: "GET", Header: http.Header{}}
	// req.SetBasicAuth(auth_config.username, auth_config.password)

	// client := get_http_client(https, verify)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("get token resp err: %s\n", string(data))
		return "", err
	}
	// fmt.Println(string(data))

	token := &registryToken{}
	err = json.Unmarshal(data, token)
	if err != nil {
		return "", err
	}
	return token.Token, nil
}

func get_http_client(verify bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: !verify},
	}
	return &http.Client{Transport: tr}

}

func get_token_server(registry string, client *http.Client) (string, string, error) {
	tUrl, err := url.Parse(registry)
	if err != nil {
		return "", "", err
	}

	tUrl.Path = "/v2/"
	// client := get_http_client(https, verify)
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

func handle_auth(registry, repo_name string, client *http.Client) string {
	realm, service, err := get_token_server(registry, client)
	if err != nil {
		panic(err)
	}

	scopes := []string{fmt.Sprintf("repository:%s:pull", repo_name)}

	token, err := get_token(realm, scopes, []string{service}, authConfig, client)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("get token: \n%s\n", token)
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

func get_manifest(base_url, tag, token string, client *http.Client) (*Manifest, error) {
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

func download_blob(base_url, b, token string, ch chan *Result, limitCh chan struct{}, client *http.Client) {
	// fmt.Printf("start pull blob %s\n", b[:20])
	start := time.Now().Unix()
	url := fmt.Sprintf("%s/blobs/%s", base_url, b)
	req, _ := http.NewRequest("GET", url, nil)
	set_token_header(req, token)
	res, err := client.Do(req)
	ioutil.ReadAll(res.Body)
	length, _ := strconv.Atoi(res.Header["Content-Length"][0])
	if err != nil {
		fmt.Printf("pull blob %s err: %s\n", b[:20], err)
	} else {
		fmt.Printf("%d pull blob %s %s\n", res.StatusCode, b[:20], getHumanreadableUnit(length))
	}
	ch <- &Result{time.Now().Unix() - start, length, b[:20]}
	<-limitCh
}

func get_blobs(base_url string, mf *Manifest, token string, blobCon int, client *http.Client) *[]*Result {
	limitCh := make(chan struct{}, blobCon)
	blobCh := make(chan *Result, len(mf.FsLayers))
	fmt.Printf("%d layers\n", len(mf.FsLayers))
	for _, layer := range mf.FsLayers {
		blob, ok := layer["blobSum"]
		if ok {
			limitCh <- struct{}{}
			go download_blob(base_url, blob, token, blobCh, limitCh, client)
		}
	}
	res := make([]*Result, len(mf.FsLayers))
	for i := range mf.FsLayers {
		// fmt.Printf("get res %d\n", i)
		res[i] = <-blobCh
	}
	// fmt.Println("get blobs ok")
	return &res
}

func pull_image(registry, repo_name, tag string, blobCon int, ch chan *[]*Result, verify bool) {
	start := time.Now().Unix()
	client := get_http_client(verify)
	base_url := fmt.Sprintf("%s/v2/%s", registry, repo_name)
	token := handle_auth(registry, repo_name, client)
	manifest, err := get_manifest(base_url, tag, token, client)
	if err != nil {
		fmt.Println("get manifest err: %s\n", err)
	}

	res := *get_blobs(base_url, manifest, token, blobCon, client)

	all := &Result{time.Now().Unix() - start, 0, ""}
	res = append(res, all)
	ch <- &res
}

func parseImageName(image string) (registry, repoName, tag string, err error) {
	compents := strings.SplitN(image, "/", 2)
	fmt.Println(image)
	if len(compents) != 2 {
		err = fmt.Errorf("invalide image name: %s, should contains \"/\"", image)
		return
	}
	registry = compents[0]
	nameTags := strings.SplitN(compents[1], ":", 2)
	if len(nameTags) == 1 {
		repoName, tag = nameTags[0], ImageDefaultTagName
	} else if len(nameTags) == 2 {
		repoName, tag = nameTags[0], nameTags[1]
	} else {
		err = fmt.Errorf("invalide repo and tag name: %s, should like busybox:0.1", compents[1])
		return
	}
	return
}

func single_test(image string, concurrence, blobCon int, https, verify bool) (int64, *[]int64) {
	registry, repoName, tag, err := parseImageName(image)
	if err != nil {
		fmt.Printf("%s, %s\n", image, err)
		return 0, nil
	}
	fmt.Printf("parse %s, %s, %s, %s\n", image, registry, repoName, tag)
	schem := "http"
	if https {
		schem = "https"
	}
	registry = fmt.Sprintf("%s://%s", schem, registry)
	start := time.Now().Unix()
	ch := make(chan *[]*Result, concurrence)
	for i := 0; i < concurrence; i++ {
		go pull_image(registry, repoName, tag, blobCon, ch, verify)
	}
	res := make([]*[]*Result, concurrence)
	for i := 0; i < concurrence; i++ {
		t := <-ch
		// fmt.Printf("t: %p\n", t)
		res[i] = t
	}
	var longest, shortest, average int64
	total := []int64{}
	// fmt.Printf("%s \n", res)
	for _, lis := range res {
		// fmt.Printf("list: %p\n", lis)
		// var all int64
		// for _, j := range *lis {
		// 	if j.Cost > longest {
		// 		longest = j.Cost
		// 	}
		// 	if j.Cost < shortest {
		// 		shortest = j.Cost
		// 	}
		// 	all += j.Cost
		// }
		total = append(total, (*lis)[len(*lis)-1].Cost)
	}
	var all int64
	for _, i := range total {
		all += i
	}
	average = all / int64(len(total))
	sort.Slice(total, func(i, j int) bool { return total[i] < total[j] })
	wholeCost := time.Now().Unix() - start
	fmt.Println()
	fmt.Println()
	fmt.Println()
	fmt.Printf("whole cost: %ds\n", wholeCost)
	fmt.Printf("%d %d %d\n pull whole image cost list\n%d\n", average, shortest, longest, total)
	return wholeCost, &total
}

func start_test(image string, concurrence, blobCon, times int, https, verify bool) {
	all_result := []int64{}
	single_results := []*[]int64{}
	for i := 0; i < times; i++ {
		costs, singleL := single_test(image, concurrence, blobCon, https, verify)
		all_result = append(all_result, costs)
		single_results = append(single_results, singleL)
	}
	var total int64
	for _, v := range all_result {
		total += v
	}
	average := total / int64(len(all_result))
	sort.Slice(all_result, func(i, j int) bool { return all_result[i] < all_result[j] })

	fmt.Println()
	fmt.Println()
	fmt.Println("all test result")
	fmt.Printf("run test %d times\n", times)
	fmt.Printf("average: %ds\n", average)
	fmt.Printf("all cost list: %v unit: s\n", all_result)
	for _, v := range single_results {
		fmt.Printf("%v \n", *v)
	}
}
