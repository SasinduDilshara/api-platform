/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package analytics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// authGoldenPath is the fixture shared with the policy-engine kernel, which stamps the
// same keys on a policy short-circuit. Both modules assert it, so the two encodings
// cannot drift apart without one of them failing.
var authGoldenPath = filepath.Join("..", "..", "testdata", "auth_analytics_golden.json")

type authGoldenLayer struct {
	Authenticated bool              `json:"authenticated"`
	Authorized    bool              `json:"authorized"`
	AuthType      string            `json:"authType"`
	Subject       string            `json:"subject"`
	Issuer        string            `json:"issuer"`
	Audience      []string          `json:"audience"`
	Scopes        []string          `json:"scopes"`
	CredentialID  string            `json:"credentialId"`
	TokenID       string            `json:"tokenId"`
	Properties    map[string]string `json:"properties"`
}

type authGolden struct {
	Auth []struct {
		Name  string            `json:"name"`
		Chain []authGoldenLayer `json:"chain"`
		Want  map[string]string `json:"want"`
	} `json:"auth"`
	Metadata []struct {
		Name     string                 `json:"name"`
		Metadata map[string]interface{} `json:"metadata"`
		Want     string                 `json:"want"`
	} `json:"metadata"`
}

func loadAuthGolden(t *testing.T) authGolden {
	t.Helper()
	data, err := os.ReadFile(authGoldenPath)
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	var g authGolden
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("parse golden fixture: %v", err)
	}
	return g
}

func goldenChain(layers []authGoldenLayer) *policy.AuthContext {
	var head *policy.AuthContext
	for i := len(layers) - 1; i >= 0; i-- {
		l := layers[i]
		ac := &policy.AuthContext{
			Authenticated: l.Authenticated, Authorized: l.Authorized, AuthType: l.AuthType,
			Subject: l.Subject, Issuer: l.Issuer, Audience: l.Audience, CredentialID: l.CredentialID,
			TokenId: l.TokenID, Properties: l.Properties, Previous: head,
		}
		if len(l.Scopes) > 0 {
			ac.Scopes = map[string]bool{}
			for _, s := range l.Scopes {
				ac.Scopes[s] = true
			}
		}
		head = ac
	}
	return head
}

func TestPopulateAuthAnalyticsMetadata_Golden(t *testing.T) {
	for _, tc := range loadAuthGolden(t).Auth {
		t.Run(tc.Name, func(t *testing.T) {
			got := map[string]any{}
			populateAuthAnalyticsMetadata(got, goldenChain(tc.Chain))
			want := map[string]any{}
			for k, v := range tc.Want {
				want[k] = v
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %v\nwant %v", got, want)
			}
		})
	}
}

func TestPopulateGenericMetadata_Golden(t *testing.T) {
	for _, tc := range loadAuthGolden(t).Metadata {
		t.Run(tc.Name, func(t *testing.T) {
			got := map[string]any{}
			populateGenericMetadata(got, tc.Metadata)
			if tc.Want == "" {
				if _, ok := got[GenericMetadataKey]; ok {
					t.Errorf("expected no %s, got %v", GenericMetadataKey, got[GenericMetadataKey])
				}
				return
			}
			if got[GenericMetadataKey] != tc.Want {
				t.Errorf("got %v, want %s", got[GenericMetadataKey], tc.Want)
			}
		})
	}
}

// api-key-auth (v1.2.1, bundled at this tag) authenticates without a Subject. The
// layer is still exported — type, token id fingerprint, application properties — but
// no user id is invented for it.
func TestPopulateAuthAnalyticsMetadata_APIKeyLayerWithoutSubject(t *testing.T) {
	metadata := map[string]any{}
	populateAuthAnalyticsMetadata(metadata, &policy.AuthContext{
		Authenticated: true, AuthType: "apikey", TokenId: "fp",
		Properties: map[string]string{"ApplicationID": "app-1"},
	})
	if _, ok := metadata[AuthUserIDMetadataKey]; ok {
		t.Errorf("no subject -> no %s, got %v", AuthUserIDMetadataKey, metadata)
	}
	if metadata[AuthTypeMetadataKey] != "apikey" || metadata[AuthTokenIDMetadataKey] != "fp" {
		t.Errorf("credential-only layer must be exported, got %v", metadata)
	}
}
