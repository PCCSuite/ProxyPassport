package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/elazarl/goproxy"
)

type Config struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var acl []*net.IPNet = nil

func init() {
	rawAcl := os.Getenv("PROXYPASSPORT_ALLOW")
	if rawAcl == "" {
		return
	}
	acl = []*net.IPNet{}
	for _, v := range strings.Split(rawAcl, ";") {
		_, net, err := net.ParseCIDR(v)
		if err != nil {
			log.Fatalf("Invalid ACL %s: %v", v, err)
		}
		acl = append(acl, net)
	}
}

func main() {
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatal("Failed to read config: ", err)
	}
	config := Config{}
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatal("Failed to unmarshal config: ", err)
	}

	proxy := goproxy.NewProxyHttpServer()

	// proxy http
	proxy.Tr.Proxy = func(r *http.Request) (*url.URL, error) {
		log.Print("Proxy check: ", r.Host)
		ips, err := net.LookupIP(r.Host)
		if err != nil {
			log.Print("Failed to lookup ", r.Host, ": ", err)
		} else if len(ips) == 0 {
			log.Print("Lookup result empty: ", r.Host)
		} else {
			ip := ips[0]
			if ip.IsPrivate() || ip.IsLoopback() {
				return nil, nil
			}
		}
		return &url.URL{
			Scheme: "http",
			Host:   config.Host,
			User:   url.UserPassword(config.Username, config.Password),
		}, nil
	}

	// proxy https
	// Copied from "Basic " + base64.StdEncoding.EncodeToString([]byte(config.Username+":"+config.Password))
	proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		connectReq := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		connectReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(config.Username+":"+config.Password)))
		c, err := net.Dial(network, config.Host)
		if err != nil {
			log.Print("Failed to dial proxy: ", err)
			return nil, err
		}
		connectReq.Write(c)
		// Read response.
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, connectReq)
		if err != nil {
			c.Close()
			log.Print("Failed to read proxy response: ", err)
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			resp, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			c.Close()
			err = errors.New("proxy refused connection" + string(resp))
			log.Print(err)
			return nil, err
		}
		return c, nil
	}

	// enable verbose logging
	proxy.Verbose = true

	var listenAddr string

	if acl != nil {
		listenAddr = "0.0.0.0:11611"
	} else {
		listenAddr = "127.0.0.1:11611"
	}

	// start serving
	log.Fatal(http.ListenAndServe(listenAddr, &aclCheckHandler{
		handler: proxy,
	}))
}

type aclCheckHandler struct {
	handler http.Handler
}

func (h *aclCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !checkACL(r.RemoteAddr) {
		w.WriteHeader(400)
		w.Write([]byte("ProxyPassport: Access denied"))
		return
	}
	h.handler.ServeHTTP(w, r)
}

func checkACL(rawAddr string) bool {
	if acl == nil {
		return true
	}
	
	ip := net.ParseIP(rawAddr)
	acl := []*net.IPNet{}
	for _, v := range acl {
		if v.Contains(ip) {
			return true
		}
	}
	return false
}
