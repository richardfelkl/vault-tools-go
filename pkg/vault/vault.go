package vault

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"strconv"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/savaki/jq"
)

// Manager handles Vault operations
type Manager struct {
	client *vault.Client
}

// GetManager gets new instance of Manager
func GetManager(token string, config *vault.Config) (*Manager, error) {
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return &Manager{client: client}, nil
}

// TransitSign signs payload or SHA sum by Vault Transit engine
func (m *Manager) TransitSign(signingBytes []byte, name string, prehashed bool) ([]byte, error) {
	client := m.client.Logical()
	args := map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(signingBytes),
		"prehashed": prehashed,
	}
	b64Sign, err := client.Write("/transit/sign/"+name, args)
	if err != nil {
		return nil, err
	}
	s := strings.Split(b64Sign.Data["signature"].(string), ":")
	signature, err := base64.StdEncoding.DecodeString(s[2])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// TransitCreateCSR creates CSR signed by Vautl Transit engine
func (m *Manager) TransitCreateCSR(name string, names pkix.Name) (string, error) {
	vaultSigningPK1 := &vaultSigningPK{
		name:    name,
		manager: m,
	}
	var args = x509.CertificateRequest{
		Subject:            names,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &args, vaultSigningPK1)
	if err != nil {
		return "", err
	}
	csrPem := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
	})
	return string(csrPem[:]), nil
}

type vaultSigningPK struct {
	name    string
	pem     string
	manager *Manager
}

func (m *vaultSigningPK) Public() crypto.PublicKey {
	client := m.manager.client.Logical()
	transitKeys, err := client.Read("/transit/keys/" + m.name)
	if err != nil {
		return nil
	}
	op, _ := jq.Parse(".keys.1.public_key")
	data, _ := json.Marshal(transitKeys.Data)
	value, _ := op.Apply(data)
	key, _ := strconv.Unquote(string(value))
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	return pub
}

// Sign signs requests with Vault's transit key
func (m *vaultSigningPK) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	signedBytes, err := m.manager.TransitSign(digest, m.name, true)
	if err != nil {
		return nil, err
	}
	return signedBytes, nil
}
