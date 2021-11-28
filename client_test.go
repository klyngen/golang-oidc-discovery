package oidcdiscovery

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestPublicKey_GetCertificate(t *testing.T) {
	type fields struct {
		Key string
		Kid string
		Alg string
	}
	tests := []struct {
		name   string
		fields PublicKey
		want   string
	}{
		{name: "Bad authority", fields: PublicKey{
			Key: "CERT CONTENT",
			Kid: "some hash",
			Alg: "some alg",
		}, want: "-----BEGIN CERTIFICATE-----\n" + "CERT CONTENT" + "\n-----END CERTIFICATE-----"},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PublicKey{
				Key: tt.fields.Key,
				Kid: tt.fields.Kid,
				Alg: tt.fields.Alg,
			}
			if got := p.GetCertificate(); got != tt.want {
				t.Errorf("PublicKey.GetCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewOidcDiscoveryClient(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Send response to be tested
		rw.Header().Add("Content-Type", "application/json")
		rw.Write([]byte(`
{"issuer":"http://localhost:8082/auth/realms/test","authorization_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/auth","token_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/token","introspection_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/token/introspect","userinfo_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/userinfo","end_session_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/logout","jwks_uri":"http://localhost:8082/auth/realms/test/protocol/openid-connect/certs","check_session_iframe":"http://localhost:8082/auth/realms/test/protocol/openid-connect/login-status-iframe.html","grant_types_supported":["authorization_code","implicit","refresh_token","password","client_credentials","urn:ietf:params:oauth:grant-type:device_code","urn:openid:params:grant-type:ciba"],"response_types_supported":["code","none","id_token","token","id_token token","code id_token","code token","code id_token token"],"subject_types_supported":["public","pairwise"],"id_token_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"id_token_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"id_token_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"userinfo_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512","none"],"request_object_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"request_object_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"response_modes_supported":["query","fragment","form_post","query.jwt","fragment.jwt","form_post.jwt","jwt"],"registration_endpoint":"http://localhost:8082/auth/realms/test/clients-registrations/openid-connect","token_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"token_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"introspection_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"introspection_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"authorization_encryption_alg_values_supported":["RSA-OAEP","RSA-OAEP-256","RSA1_5"],"authorization_encryption_enc_values_supported":["A256GCM","A192GCM","A128GCM","A128CBC-HS256","A192CBC-HS384","A256CBC-HS512"],"claims_supported":["aud","sub","iss","auth_time","name","given_name","family_name","preferred_username","email","acr"],"claim_types_supported":["normal"],"claims_parameter_supported":true,"scopes_supported":["openid","profile","roles","microprofile-jwt","offline_access","phone","address","web-origins","email"],"request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,"code_challenge_methods_supported":["plain","S256"],"tls_client_certificate_bound_access_tokens":true,"revocation_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/revoke","revocation_endpoint_auth_methods_supported":["private_key_jwt","client_secret_basic","client_secret_post","tls_client_auth","client_secret_jwt"],"revocation_endpoint_auth_signing_alg_values_supported":["PS384","ES384","RS384","HS256","HS512","ES256","RS256","HS384","ES512","PS256","PS512","RS512"],"backchannel_logout_supported":true,"backchannel_logout_session_supported":true,"device_authorization_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/auth/device","backchannel_token_delivery_modes_supported":["poll","ping"],"backchannel_authentication_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/ext/ciba/auth","backchannel_authentication_request_signing_alg_values_supported":["PS384","ES384","RS384","ES256","RS256","ES512","PS256","PS512","RS512"],"require_pushed_authorization_requests":false,"pushed_authorization_request_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/ext/par/request","mtls_endpoint_aliases":{"token_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/token","revocation_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/revoke","introspection_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/token/introspect","device_authorization_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/auth/device","registration_endpoint":"http://localhost:8082/auth/realms/test/clients-registrations/openid-connect","userinfo_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/userinfo","pushed_authorization_request_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/ext/par/request","backchannel_authentication_endpoint":"http://localhost:8082/auth/realms/test/protocol/openid-connect/ext/ciba/auth"}}
`))
	}))

	// Close the server when test finishes
	defer server.Close()

	type args struct {
		authorityUrl string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "Valid OIDC configuration response", args: args{
			authorityUrl: server.URL,
		}, wantErr: false, want: "http://localhost:8082/auth/realms/test"},
		{name: "Valid OIDC configuration response ", args: args{
			authorityUrl: server.URL,
		}, wantErr: false, want: "http://localhost:8082/auth/realms/test"},
		{name: "InValid OIDC configuration response ", args: args{
			authorityUrl: "http://localhost:123",
		}, wantErr: true, want: "http://localhost:8082/auth/realms/test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewOidcDiscoveryClient(tt.args.authorityUrl)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewOidcDiscoveryClient().DiscoveryDocument().Issuer error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got != nil) && !reflect.DeepEqual(got.DiscoveryDocument().Issuer, tt.want) {
				t.Errorf("NewOidcDiscoveryClient().DiscoveryDocument().Issuer = %v, want %v", got.DiscoveryDocument().Issuer, tt.want)
			}
		})
	}
}

func TestOidcDiscoveryClient_GetCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Send response to be tested
		rw.Header().Add("Content-Type", "application/json")
		rw.Write([]byte(`{"keys":[{"kid":"WLwfibwN41GLOiaLJZFOdwZOtNvaOApz6gUrb9zIKMY","kty":"RSA","alg":"RS256","use":"enc","n":"ps2F8jwFL8Qt7o1R7UutNIg2outJaVF1l4u0u-Rc2iDOMDvyFRF9ulaS3tQdJXtSpLsizc7Tx60N3htJ7uBjVnTrH4a2m2EzbzG0Xt_-MURIXdqS7dJLDoJhOU2QE8gEpziEwukmzCDxs88E60_Wmqrfu9hnEAuqS7es1_ylyKXYXkj9FWciOotRcmra1njeUNwlBGCXJWXtG5bTk-xoMq0mf4iaG3IE_6AH6P6SsiUC4elfoIIDqKQv3kqG16Hcmg80czgkSpWJGcxisNz9vafpKSz9pFjVPLhrX_MsVp5xjvlkCNjnOQ_Pj3FoW4_sXkBnOMNou8I6xyYPzTDsyQ","e":"AQAB","x5c":["MIIClzCCAX8CBgF9RBWo3zANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDAR0ZXN0MB4XDTIxMTEyMTE5NTgyOVoXDTMxMTEyMTIwMDAwOVowDzENMAsGA1UEAwwEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbNhfI8BS/ELe6NUe1LrTSINqLrSWlRdZeLtLvkXNogzjA78hURfbpWkt7UHSV7UqS7Is3O08etDd4bSe7gY1Z06x+GtpthM28xtF7f/jFESF3aku3SSw6CYTlNkBPIBKc4hMLpJswg8bPPBOtP1pqq37vYZxALqku3rNf8pcil2F5I/RVnIjqLUXJq2tZ43lDcJQRglyVl7RuW05PsaDKtJn+ImhtyBP+gB+j+krIlAuHpX6CCA6ikL95Khteh3JoPNHM4JEqViRnMYrDc/b2n6Sks/aRY1Ty4a1/zLFaecY75ZAjY5zkPz49xaFuP7F5AZzjDaLvCOscmD80w7MkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAKjnh+OIyF9seqPb0dsE4MiRwFOeGtbl66SNFAQ9ukJFLXSWpQLx0/AdqY+8CtIOEoo9pAOJnMMjoywGjxl+DWitfbhuYb8b7K79qHN5tBWXFLOajghnGudnDCfChdscMYUqr7zHxcoxheLcJEYm435T6fPekL3u4ts67kbmocvI3W+j2v4ptVoNcl627Rf1+JIXjIA4uFxKg4kG6QD6jFFJsCq0GJmmYoQ2lZr3vDFkw2JRbIE0PXKCsPfawRWQACqyWLSQ6HgclAF564+TWl/gaFoP575GzBfJv1/76FMikmEbJ2ewWzY56L8T175XcydnMz3xOb4xjKYEYREfAGw=="],"x5t":"4jrH5WJHR3UR1Xt-Z27RyM6J1Cs","x5t#S256":"WpMcR4xfEL8ilFVJHRoBY8ANa_eg7IzIrt8ZgsE4qQU"},{"kid":"7XTFJl6IUuQ_xHf9_B6ytVBKNnBXiVqHoAXJ9snNO1k","kty":"RSA","alg":"RS256","use":"sig","n":"kdDUw4wkwpasBaPOXrkZYW4irf7mH9mFq2iV_mnoD8Ws1Liwvvgb6S3q0L2VnaQppyZa1vN5Xn4dDvKrvnqqf4-C_NHe3BBNJ7HVE3kwWBAg0Ji5LZre53PrEcH23Ji2Zw2aYJTQzV5x1F1UnRb5PngEpyBE6HEVgGkUawq04zicuYc3hS1JSYsD947L-JbGTo7E_kmka8O-i39wFU5W9FFsgkz-0CVkFkCRpqZWYiB2e-z3x1JP0DQNY5ARKqT9Wem7jd6Oe9_6GXfDgqFNT85iBOnCbnpjtN0NUEeF3GpsX68sY23VqnqteQMt5E53vggK1gfIDloRFg9zdqotPQ","e":"AQAB","x5c":["MIIClzCCAX8CBgF9RBWn4zANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDAR0ZXN0MB4XDTIxMTEyMTE5NTgyOVoXDTMxMTEyMTIwMDAwOVowDzENMAsGA1UEAwwEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJHQ1MOMJMKWrAWjzl65GWFuIq3+5h/Zhatolf5p6A/FrNS4sL74G+kt6tC9lZ2kKacmWtbzeV5+HQ7yq756qn+PgvzR3twQTSex1RN5MFgQINCYuS2a3udz6xHB9tyYtmcNmmCU0M1ecdRdVJ0W+T54BKcgROhxFYBpFGsKtOM4nLmHN4UtSUmLA/eOy/iWxk6OxP5JpGvDvot/cBVOVvRRbIJM/tAlZBZAkaamVmIgdnvs98dST9A0DWOQESqk/Vnpu43ejnvf+hl3w4KhTU/OYgTpwm56Y7TdDVBHhdxqbF+vLGNt1ap6rXkDLeROd74ICtYHyA5aERYPc3aqLT0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAGWlg6CbmZ8CjJ755k1Zk4SxLYA5CnSw76DwuCg45LutZhImXGY0KHwij18lKH1Ua5k2wCZ8BA9kp4AZtS3qogDn0DxhtA7tmL+Fs7CEzt2kvV1wiPh4Ub8Dog2Cy99AzaNiIGKd+kKUo9HR2/wbUCrdkndoBDRkHzfka+8CkUBss34+OgX0x/3QWXhgSC5FCG3LbdURV/WAhiADxPamiIVK9CQB3Inhu45ZIDmyrCpqnXDqKfP2lyr3kpcDrQ984jpAvBRpWrRY/ADE9YUYipMAORS50LlT3E4BZdKRvAo0sr7I7iFlvc97/MfuLy3T6+OV6Y6JOF77FgYk7C3lQvQ=="],"x5t":"V9aZVcYMyRtAH3TKqza73hhUQoc","x5t#S256":"5npMjsqIQSpbpmacrPYlF3d9Sno46f9ArxWvXKat1MM"}]}`))
	}))
	defer server.Close()
	type fields struct {
		discoveryDocument DiscoveryDocument
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{name: "Successfully fetching data",
			fields: fields{
				discoveryDocument: DiscoveryDocument{
					JwksURI: server.URL,
				},
			}, want: "MIIClzCCAX8CBgF9RBWo3zANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDAR0ZXN0MB4XDTIxMTEyMTE5NTgyOVoXDTMxMTEyMTIwMDAwOVowDzENMAsGA1UEAwwEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbNhfI8BS/ELe6NUe1LrTSINqLrSWlRdZeLtLvkXNogzjA78hURfbpWkt7UHSV7UqS7Is3O08etDd4bSe7gY1Z06x+GtpthM28xtF7f/jFESF3aku3SSw6CYTlNkBPIBKc4hMLpJswg8bPPBOtP1pqq37vYZxALqku3rNf8pcil2F5I/RVnIjqLUXJq2tZ43lDcJQRglyVl7RuW05PsaDKtJn+ImhtyBP+gB+j+krIlAuHpX6CCA6ikL95Khteh3JoPNHM4JEqViRnMYrDc/b2n6Sks/aRY1Ty4a1/zLFaecY75ZAjY5zkPz49xaFuP7F5AZzjDaLvCOscmD80w7MkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAKjnh+OIyF9seqPb0dsE4MiRwFOeGtbl66SNFAQ9ukJFLXSWpQLx0/AdqY+8CtIOEoo9pAOJnMMjoywGjxl+DWitfbhuYb8b7K79qHN5tBWXFLOajghnGudnDCfChdscMYUqr7zHxcoxheLcJEYm435T6fPekL3u4ts67kbmocvI3W+j2v4ptVoNcl627Rf1+JIXjIA4uFxKg4kG6QD6jFFJsCq0GJmmYoQ2lZr3vDFkw2JRbIE0PXKCsPfawRWQACqyWLSQ6HgclAF564+TWl/gaFoP575GzBfJv1/76FMikmEbJ2ewWzY56L8T175XcydnMz3xOb4xjKYEYREfAGw==",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &OidcDiscoveryClient{
				discoveryDocument: tt.fields.discoveryDocument,
			}
			got, err := c.GetCertificates()
			if (err != nil) != tt.wantErr {
				t.Errorf("OidcDiscoveryClient.GetCertificates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got[0].Key, tt.want) {
				t.Errorf("OidcDiscoveryClient.GetCertificates() = %v, want %v", got, tt.want)
			}
		})
	}
}
