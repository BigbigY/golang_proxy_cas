/*
TODO:
1. session encrypt
2. session expire time
*/
package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	CAS_URL          = "https://cas.xx.com"
	CookieExpireTime = 48 // 2 days
)

var (
	localhost = flag.String("localhost", "0.0.0.0", "local address")
	localport = flag.Int("localport", 8888, "local port")
	dsthost   = flag.String("dsthost", "", "server address")
	dstport   = flag.Int("dstport", 80, "server port")
)

type handle struct {
	host string
	port int
}

func (this *handle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user_cookie, err := r.Cookie("session")
	if err != nil {
		fmt.Printf("get cookie err: %s\n", err)
		http.Redirect(w, r, "/login", 301)
	} else {
		if time.Now().Sub(user_cookie.Expires) <= 0 {
			http.Redirect(w, r, "/login", 301)
		}
	}
	remote, err := url.Parse(fmt.Sprintf("http://%s:%d", *dsthost, *dstport))
	if err != nil {
		fmt.Printf("parse url err: %s\n", err)
		os.Exit(1)
	}
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.ServeHTTP(w, r)
}

func main() {
	flag.Parse()
	if *dsthost == "" {
		fmt.Println("-h to get help message")
		os.Exit(1)
	}

	// login handle
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("login url: ", r.RequestURI)
		if strings.Contains(r.RequestURI, "?ticket=") {
			queryurl := strings.Split(r.RequestURI, "?")
			values, err := url.ParseQuery(queryurl[1])
			if err != nil {
				fmt.Printf("url parse query %s err: %s\n", queryurl[1], err)
				return
			}
			ticket := values.Get("ticket")
			data, err := ValidateTicket(queryurl[0], ticket)
			if err != nil {
				fmt.Printf("validate ticket err: %s\n", err)
				return
			}
			results := strings.Split(data, "\n")
			if results[0] != "yes" {
				http.Redirect(w, r, "/logout", 301)
			} else {
				cookie := &http.Cookie{Name: "session", Value: EncodeCookie(results[1]), Expires: time.Now().Add(CookieExpireTime * time.Hour)}
				http.SetCookie(w, cookie)
				http.Redirect(w, r, "/", 301)
			}
		} else {
			cas_login_url := fmt.Sprintf("%s/login?service=%s", CAS_URL, url.QueryEscape(r.RequestURI))
			http.Redirect(w, r, cas_login_url, 301)
		}
	})

	// logout handle
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		cas_logout_url := fmt.Sprintf("%s/logout", CAS_URL)
		cookie := &http.Cookie{Name: "session", MaxAge: -1}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, cas_logout_url, 301)
	})

	// proxy handle
	proxyhandle := &handle{host: *dsthost, port: *dstport}
	http.Handle("/", proxyhandle)

	// listen
	localaddr := fmt.Sprintf("%s:%d", *localhost, *localport)
	err := http.ListenAndServe(localaddr, nil)
	if err != nil {
		fmt.Printf("listen port 8888 err: %s\n", err)
		return
	}
}

func ValidateTicket(uri, ticket string) (string, error) {
	if ticket != "" {
		cas_valid_url := fmt.Sprintf("%s/validate?service=%s&ticket=%s", CAS_URL, url.QueryEscape(uri), ticket)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Get(cas_valid_url)
		if err != nil {
			fmt.Printf("validate ticket err: %s\n", err)
			return "", err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("validate ticket read body err: %s\n", err)
			return "", err
		}
		return string(body), nil
	} else {
		return "", errors.New("unknown ticket")
	}
}

func EncodeCookie(src string) string {
	return base64.StdEncoding.EncodeToString([]byte(src))
}

func DecodeCookie(src string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return "", err
	} else {
		return string(data), nil
	}
}
