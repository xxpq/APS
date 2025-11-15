package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func (p *MapRemoteProxy) handleConnectWithIntercept(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	log.Printf("[CONNECT] %s", host)

	hostname := strings.Split(r.Host, ":")[0]
	shouldIntercept := p.shouldInterceptHost(hostname)

	if shouldIntercept {
		log.Printf("[CONNECT] Intercepting HTTPS for mapping: %s", r.Host)
		p.handleConnectWithMITM(w, r)
	} else {
		log.Printf("[CONNECT] Tunneling without intercept: %s", r.Host)
		p.handleConnectTunnel(w, r, host)
	}
}

func (p *MapRemoteProxy) shouldInterceptHost(hostname string) bool {
	mappings := p.config.GetMappings()
	for _, mapping := range mappings {
		fromURL := mapping.GetFromURL()
		if strings.HasPrefix(fromURL, "https://"+hostname) {
			log.Printf("[DEBUG] Host %s matches mapping pattern %s", hostname, fromURL)
			return true
		}
	}
	return false
}

func (p *MapRemoteProxy) handleConnectWithMITM(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusServiceUnavailable)
		log.Printf("Error hijacking connection: %v", err)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("Error writing 200 OK to client: %v", err)
		return
	}

	hostname := strings.Split(r.Host, ":")[0]

	tlsClientConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return GenerateCertForHost(hostname)
		},
	})
	defer tlsClientConn.Close()

	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
		return
	}

	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading HTTPS request: %v", err)
			}
			break
		}

		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		if !strings.HasPrefix(req.RequestURI, "http") {
			req.RequestURI = "https://" + r.Host + req.RequestURI
		}

		// 在这里处理被拦截的 HTTPS 请求
		p.handleHTTP(w, req)
	}
}

func (p *MapRemoteProxy) handleConnectTunnel(w http.ResponseWriter, r *http.Request, destHost string) {
	destConn, err := net.DialTimeout("tcp", destHost, 10*time.Second)
	if err != nil {
		http.Error(w, "Failed to connect to destination", http.StatusServiceUnavailable)
		log.Printf("Error connecting to %s: %v", destHost, err)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusServiceUnavailable)
		log.Printf("Error hijacking connection: %v", err)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("Error writing 200 OK to client: %v", err)
		return
	}

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(destConn, clientConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()

	<-done
	log.Printf("[CONNECT] %s - Connection closed", r.Host)
}

// modifyResponseBody 移动到 http_handler.go
func (p *MapRemoteProxy) modifyResponseBody(resp *http.Response, mapping *Mapping) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	if mapping == nil {
		return body, nil
	}

	toConfig := mapping.GetToConfig()
	if toConfig == nil {
		return body, nil
	}

	if toConfig.Match != "" {
		re, err := compileRegex(toConfig.Match)
		if err != nil {
			log.Printf("Invalid match regex in 'to' config: %v", err)
			return body, nil
		}
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			body = matches[1]
			log.Printf("[RESPONSE MATCH] Extracted %d bytes from response body", len(body))
		} else {
			body = []byte{}
			log.Printf("[RESPONSE MATCH] No match found, returning empty body")
		}
	}

	if len(toConfig.Replace) > 0 {
		tempBody := string(body)
		for key, value := range toConfig.Replace {
			re, err := compileRegex(key)
			if err != nil {
				log.Printf("Invalid replace regex in 'to' config: %v", err)
				continue
			}
			tempBody = re.ReplaceAllString(tempBody, value)
			log.Printf("[RESPONSE REPLACE] Applied replacement: %s -> %s", key, value)
		}
		body = []byte(tempBody)
	}

	return body, nil
}