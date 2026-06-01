// agents/cell/recon/http.go
// HTTP/HTTPS fingerprint module — banner, headers, technology detection, common paths.

package recon

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type HTTPResult struct {
	IP           string
	Port         int
	StatusCode   int
	Server       string
	XPoweredBy   string
	SetCookie    []string
	WWWAuth      string
	Title        string
	Technologies []string
	Redirect     string
	Robots       bool
	Error        string
}

const httpUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		MaxIdleConns:        1,
		IdleConnTimeout:     1 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// techFingerprints maps regex patterns to technology names
var techFingerprints = map[string]*regexp.Regexp{
	"jQuery":      regexp.MustCompile(`jquery[/-]([\d.]+)(?:\.min)?\.js`),
	"Bootstrap":   regexp.MustCompile(`bootstrap[/-]([\d.]+)(?:\.min)?\.(?:css|js)`),
	"WordPress":   regexp.MustCompile(`wp-content/|wp-includes/|<meta name="generator" content="WordPress`),
	"PHP":         regexp.MustCompile(`<meta name="generator" content="PHP`),
	"React":       regexp.MustCompile(`react[/-]([\d.]+)(?:\.production)?\.min\.js`),
	"Vue.js":      regexp.MustCompile(`vue[/-]([\d.]+)(?:\.production)?\.min\.js`),
	"Angular":     regexp.MustCompile(`ng-version="([^"]+)"`),
	"Django":      regexp.MustCompile(`csrftoken`),
	"Laravel":     regexp.MustCompile(`laravel_session`),
	"ASP.NET":     regexp.MustCompile(`__VIEWSTATE|__EVENTVALIDATION`),
	"Tomcat":      regexp.MustCompile(`Apache Tomcat/([\d.]+)`),
	"Jenkins":     regexp.MustCompile(`Jenkins ([\d.]+)|X-Jenkins`),
	"phpMyAdmin":  regexp.MustCompile(`phpMyAdmin ([\d.]+)`),
	"Cloudflare":  regexp.MustCompile(`__cfduid|cf-ray|Server: cloudflare`),
	"Nginx":       regexp.MustCompile(`Server: nginx`),
}

// titleRe extracts <title>...</title> from HTML
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// FingerprintHTTP performs HTTP fingerprint on target:port
func FingerprintHTTP(target string, port int, useTLS bool) *HTTPResult {
	res := &HTTPResult{IP: target, Port: port}

	scheme := "http"
	if useTLS || port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s:%d/", scheme, target, port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", httpUserAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.Server = resp.Header.Get("Server")
	res.XPoweredBy = resp.Header.Get("X-Powered-By")
	res.WWWAuth = resp.Header.Get("WWW-Authenticate")

	for _, v := range resp.Header.Values("Set-Cookie") {
		res.SetCookie = append(res.SetCookie, strings.SplitN(v, ";", 2)[0])
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		res.Redirect = loc
	}

	// Read body (first 128KB)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	bodyStr := string(body)

	// Extract title
	if m := titleRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		res.Title = strings.TrimSpace(m[1])
	}

	// Technology detection
	for tech, re := range techFingerprints {
		if re.MatchString(bodyStr) || re.MatchString(res.Server) {
			res.Technologies = append(res.Technologies, tech)
		}
	}

	// Check robots.txt
	robotsURL := fmt.Sprintf("%s://%s:%d/robots.txt", scheme, target, port)
	robotsReq, _ := http.NewRequest("GET", robotsURL, nil)
	robotsReq.Header.Set("User-Agent", httpUserAgent)
	if r, err := httpClient.Do(robotsReq); err == nil {
		r.Body.Close()
		res.Robots = r.StatusCode == 200
	}

	return res
}

// CommonWebPaths are paths to check for information disclosure
var CommonWebPaths = []string{
	"/.git/HEAD", "/.env", "/.env.backup", "/.htaccess",
	"/wp-login.php", "/wp-admin/", "/wp-content/",
	"/administrator/", "/phpmyadmin/", "/phpMyAdmin/",
	"/manager/html", "/host-manager/html", "/_profiler",
	"/swagger.json", "/api/v1/", "/graphql", "/graphiql",
	"/console/", "/_debug/", "/info.php", "/phpinfo.php",
	"/server-status", "/server-info", "/.DS_Store",
	"/sitemap.xml", "/crossdomain.xml", "/backup/",
	"/admin/", "/login/", "/wp-json/", "/api/",
}

// CheckCommonPaths tests common paths and returns those found
func CheckCommonPaths(target string, port int, useTLS bool) map[string]int {
	scheme := "http"
	if useTLS || port == 443 || port == 8443 {
		scheme = "https"
	}
	found := make(map[string]int)
	client := &http.Client{Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	for _, path := range CommonWebPaths {
		url := fmt.Sprintf("%s://%s:%d%s", scheme, target, port, path)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", httpUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			found[path] = resp.StatusCode
		}
	}
	return found
}
