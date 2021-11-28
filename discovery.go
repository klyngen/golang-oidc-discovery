package oidcdiscovery

// DiscoveryDocument is the discovery document structure
type DiscoveryDocument struct {
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	IDTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	UserinfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	JwksURI                                    string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	RequireRequestURIRegistration              bool     `json:"require_request_uri_registration"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported"`
	ServiceDocumentation                       string   `json:"service_documentation"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	UserinfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported"`
	OpTosURI                                   string   `json:"op_tos_uri"`
	Issuer                                     string   `json:"issuer"`
	OpPolicyURI                                string   `json:"op_policy_uri"`
	ClaimsSupported                            []string `json:"claims_supported"`
}

// JwksEndpointResponse is the response from the JWKS-endoint
type JwksEndpointResponse struct {
	Keys []struct {
		Kid     string   `json:"kid"`
		Kty     string   `json:"kty"`
		Alg     string   `json:"alg"`
		Use     string   `json:"use"`
		N       string   `json:"n"`
		E       string   `json:"e"`
		X5C     []string `json:"x5c"`
		X5T     string   `json:"x5t"`
		X5TS256 string   `json:"x5t#S256"`
	} `json:"keys"`
}
