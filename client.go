package oidcdiscovery

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"
)

type PublicKey struct {
	Key string
	Kid string
	Alg string
}

// GetCertificate the key in the public key is without the
// BEGIN and END. This function returns a valid certificate
func (p *PublicKey) GetCertificate() string {
	return "-----BEGIN CERTIFICATE-----\n" + p.Key + "\n-----END CERTIFICATE-----"
}

// OidcDiscoveryClient describes a OIDC Configuration of a
// given authority
type OidcDiscoveryClient struct {
	discoveryDocument DiscoveryDocument
}

// NewOidcDiscoveryClient instantiates a new confiuration
func NewOidcDiscoveryClient(authorityUrl string) (*OidcDiscoveryClient, error) {
	requestUrl, err := url.Parse(authorityUrl)

	if err != nil {
		return nil, errors.Wrap(err, "Unable to parse the given authority")
	}

	requestUrl.Path = path.Join(requestUrl.Path, ".well-known/openid-configuration")

	resp, err := http.Get(requestUrl.String())

	if err != nil {
		return nil, errors.Wrap(err, "Unable to fetch the discovery document")
	}

	jsonBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, errors.Wrapf(err, "Could not read the response body from: %v", authorityUrl)
	}

	var dicsovery DiscoveryDocument
	json.Unmarshal(jsonBytes, &dicsovery)

	return &OidcDiscoveryClient{
		discoveryDocument: dicsovery,
	}, nil
}

// DiscoveryDocument returns the current discovery document
func (c *OidcDiscoveryClient) DiscoveryDocument() DiscoveryDocument {
	return c.discoveryDocument
}

// GetCertificates gets the certificates and returns a handy struct
func (c *OidcDiscoveryClient) GetCertificates() ([]PublicKey, error) {
	resp, err := http.Get(c.discoveryDocument.JwksURI)

	if err != nil {
		errors.Wrapf(err, "Unable to get response from Jwks-endpoint %v", c.discoveryDocument.JwksURI)
	}

	jsonBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil || jsonBytes == nil {
		return nil, errors.Wrapf(err, "Could not read the response body from: %v", c.discoveryDocument.JwksURI)
	}

	var jwks JwksEndpointResponse

	err = json.Unmarshal(jsonBytes, &jwks)

	if err != nil {
		return nil, errors.Wrap(err, "Unable to parse json")
	}

	result := make([]PublicKey, len(jwks.Keys))
	for i, key := range jwks.Keys {
		result[i] = PublicKey{
			Alg: key.Alg,
			Key: key.X5C[0],
			Kid: key.Kid,
		}
	}

	return result, nil

}
