package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

var (
	certCache = make(map[string]*tls.Certificate)
	certMutex sync.RWMutex
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	caCertPEM []byte
	acmeManager *autocert.Manager
)

const (
	certDir      = ".cert"
	acmeDir      = ".cert/acme"
	caCertFile   = "Any_Proxy_Service.crt"
	caKeyFile    = "Any_Proxy_Service.key"
	caCommonName = "Any Proxy Service Root CA"
	caOrg        = "Any Proxy Service"
)

func InitCertificates() error {
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return err
	}

	certPath := filepath.Join(certDir, caCertFile)
	keyPath := filepath.Join(certDir, caKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		log.Printf("Loading existing root certificate from %s", certDir)
		cert, key, certPEM, err := loadCA(certPath, keyPath)
		if err != nil {
			log.Printf("Failed to load existing certificate, generating new one: %v", err)
			return generateAndSaveCA(certPath, keyPath)
		}
		caCert = cert
		caKey = key
		caCertPEM = certPEM
		log.Printf("Root certificate loaded successfully")
		return nil
	}

	log.Printf("Root certificate not found, generating new one...")
	return generateAndSaveCA(certPath, keyPath)
}

func generateAndSaveCA(certPath, keyPath string) error {
	cert, key, err := generateCA()
	if err != nil {
		return err
	}

	certPEM, keyPEM, err := encodeCertAndKey(cert, key)
	if err != nil {
		return err
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}

	caCert = cert
	caKey = key
	caCertPEM = certPEM

	log.Printf("Root certificate generated and saved to %s", certDir)
	log.Printf("Certificate file: %s", certPath)
	log.Printf("Please install the root certificate to trust HTTPS interception")
	return nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, nil, os.ErrInvalid
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, nil, os.ErrInvalid
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return cert, key, certPEM, nil
}

func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization: []string{caOrg},
			CommonName:   caCommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	ca, err = x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}

	return ca, caPrivKey, nil
}

func encodeCertAndKey(cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, []byte, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return certPEM, keyPEM, nil
}

func GenerateCertForHost(host string) (*tls.Certificate, error) {
	certMutex.RLock()
	if cert, ok := certCache[host]; ok {
		certMutex.RUnlock()
		return cert, nil
	}
	certMutex.RUnlock()

	certMutex.Lock()
	defer certMutex.Unlock()

	if cert, ok := certCache[host]; ok {
		return cert, nil
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{caOrg},
			CommonName:   host,
		},
		DNSNames:    []string{host},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes, caCert.Raw},
		PrivateKey:  certPrivKey,
	}

	certCache[host] = tlsCert
	return tlsCert, nil
}

func GetCACertPEM() []byte {
	return caCertPEM
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// InitACME initializes the ACME certificate manager.
func InitACME(config *Config) {
	// 从配置中收集所有需要ACME证书的域名
	var acmeDomains []string
	for _, mapping := range config.Mappings {
		// 检查与此mapping关联的server是否配置了acme
		for _, serverName := range mapping.serverNames {
			if server, ok := config.Servers[serverName]; ok {
				if certStr, ok := server.Cert.(string); ok && certStr == "acme" {
					// 从 "from" URL 中提取域名
					domain := extractDomain(mapping.GetFromURL())
					if domain != "" && !containsString(acmeDomains, domain) {
						acmeDomains = append(acmeDomains, domain)
					}
				}
			}
		}
	}

	if len(acmeDomains) == 0 {
		log.Println("[ACME] No domains configured for ACME, skipping initialization.")
		return
	}

	log.Printf("[ACME] Initializing for domains: %v", acmeDomains)

	// 确保ACME缓存目录存在
	if err := os.MkdirAll(acmeDir, 0755); err != nil {
		log.Fatalf("[ACME] Failed to create cache directory: %v", err)
	}

	acmeManager = &autocert.Manager{
		Cache:      autocert.DirCache(acmeDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(acmeDomains...),
	}
}

// GetACMETLSConfig returns a TLS config for ACME.
func GetACMETLSConfig() *tls.Config {
	if acmeManager == nil {
		return nil
	}
	return acmeManager.TLSConfig()
}

// GetACMEHandler returns the HTTP handler for the ACME challenge.
func GetACMEHandler(fallback http.Handler) http.Handler {
	if acmeManager == nil {
		return fallback
	}
	return acmeManager.HTTPHandler(fallback)
}
