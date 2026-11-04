/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package kernel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/analytics/dto"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/constants"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/executor"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// shortCircuitCtx builds the minimal execution context collectShortCircuitAnalytics
// reads: the accumulated analytics, the shared context, and the request body context
// mergePolicyAnalytics consults for header filters.
func shortCircuitCtx(sc *policy.SharedContext) *PolicyExecutionContext {
	return &PolicyExecutionContext{
		analyticsMetadata: map[string]interface{}{},
		sharedCtx:         sc,
		requestBodyCtx:    &policy.RequestContext{SharedContext: sc},
	}
}

func deny(status int, meta map[string]any) policy.ImmediateResponse {
	return policy.ImmediateResponse{StatusCode: status, AnalyticsMetadata: meta}
}

// The kernel and the publisher agree on every key by spelling; the analytics package
// copies these 1:1 into Event.Properties under the dto constants.
func TestShortCircuitAudit_KeysMatchTheEventPropertyKeys(t *testing.T) {
	pairs := map[string]string{
		AuthUserIDKey:            dto.PropKeyAuthUserID,
		AuthTypeKey:              dto.PropKeyAuthType,
		AuthIssuerKey:            dto.PropKeyAuthIssuer,
		AuthCredentialIDKey:      dto.PropKeyAuthCredentialID,
		AuthTokenIDKey:           dto.PropKeyAuthTokenID,
		AuthAudienceKey:          dto.PropKeyAuthAudience,
		AuthScopesKey:            dto.PropKeyAuthScopes,
		AuthPropertiesKey:        dto.PropKeyAuthProperties,
		AuthAuthorizedKey:        dto.PropKeyAuthAuthorized,
		GenericMetadataKey:       dto.PropKeyMetadata,
		TerminalReasonKey:        dto.PropKeyTerminalReason,
		DeniedByPolicyKey:        dto.PropKeyDeniedByPolicy,
		DeniedByPolicyVersionKey: dto.PropKeyDeniedByPolicyVersion,
		DeniedPhaseKey:           dto.PropKeyDeniedPhase,
	}
	for kernelKey, propKey := range pairs {
		assert.Equal(t, propKey, kernelKey)
	}
	assert.Equal(t, "x-wso2-denied-by-policy", DeniedByPolicyKey)
	assert.Equal(t, "x-wso2-denied-by-policy-version", DeniedByPolicyVersionKey)
	assert.Equal(t, "x-wso2-denied-phase", DeniedPhaseKey)
}

// The expected strings are exactly what populateAuthAnalyticsMetadata in
// gateway/system-policies/analytics/analytics.go produces for the same AuthContext
// (audience comma-joined, scopes sorted and space-joined, properties JSON, authorized
// "true"/"false"). The two must stay byte-identical so the publisher parses one format.
func TestAuthAnalyticsMetadata_EncodesLikeTheCollector(t *testing.T) {
	tests := []struct {
		name string
		auth *policy.AuthContext
		want map[string]any
	}{
		{
			name: "nil context stamps nothing",
			auth: nil,
			want: nil,
		},
		{
			name: "unauthenticated context stamps nothing",
			auth: &policy.AuthContext{Authenticated: false, Subject: "alice"},
			want: nil,
		},
		{
			name: "authenticated without subject stamps nothing",
			auth: &policy.AuthContext{Authenticated: true},
			want: nil,
		},
		{
			name: "full jwt layer",
			auth: &policy.AuthContext{
				Authenticated: true,
				Authorized:    true,
				AuthType:      "jwt",
				Subject:       "alice",
				Issuer:        "https://idp.example.com",
				Audience:      []string{"aud-a", "aud-b"},
				Scopes:        map[string]bool{"write": true, "read": true, "admin": true},
				CredentialID:  "client-1",
				TokenId:       "jti-1",
				Properties:    map[string]string{"act": `{"sub":"agent-1"}`, "tenant": "t1"},
			},
			want: map[string]any{
				"x-wso2-user-id":            "alice",
				"x-wso2-auth-type":          "jwt",
				"x-wso2-auth-issuer":        "https://idp.example.com",
				"x-wso2-auth-credential-id": "client-1",
				"x-wso2-auth-token-id":      "jti-1",
				"x-wso2-auth-audience":      "aud-a,aud-b",
				"x-wso2-auth-scopes":        "admin read write",
				"x-wso2-auth-properties":    `{"act":"{\"sub\":\"agent-1\"}","tenant":"t1"}`,
				"x-wso2-auth-authorized":    "true",
			},
		},
		{
			name: "authorization false is still stamped",
			auth: &policy.AuthContext{Authenticated: true, Subject: "bob", AuthType: "mcp/oauth"},
			want: map[string]any{
				"x-wso2-user-id":         "bob",
				"x-wso2-auth-type":       "mcp/oauth",
				"x-wso2-auth-authorized": "false",
			},
		},
		{
			name: "chain: first authenticated layer with a subject wins",
			auth: &policy.AuthContext{
				Authenticated: false, Subject: "outer-unauth",
				Previous: &policy.AuthContext{
					Authenticated: true, AuthType: "apikey", // no subject: skipped
					Previous: &policy.AuthContext{
						Authenticated: true, Subject: "inner", AuthType: "jwt",
						Previous: &policy.AuthContext{Authenticated: true, Subject: "deeper"},
					},
				},
			},
			want: map[string]any{
				"x-wso2-user-id":         "inner",
				"x-wso2-auth-type":       "jwt",
				"x-wso2-auth-authorized": "false",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, authAnalyticsMetadata(tt.auth))
		})
	}
}

func TestGenericMetadataAnalytics_MirrorsTheCollectorFilter(t *testing.T) {
	assert.Equal(t, "", genericMetadataAnalytics(nil))
	assert.Equal(t, "", genericMetadataAnalytics(map[string]interface{}{"__analytics_stream_acc": []byte("x")}),
		"only internal keys -> nothing exported")
	assert.Equal(t, `{"mcp.tool":"orderPizza","n":2}`, genericMetadataAnalytics(map[string]interface{}{
		"mcp.tool":            "orderPizza",
		"n":                   2,
		"__a2a_request_start": 123,
		"__a2a_first_event":   1,
		"__a2a_stream_scan":   0,
	}))
}

func TestCollectShortCircuitAnalytics_StampsTheDenyingPolicy(t *testing.T) {
	allow := policy.UpstreamRequestHeaderModifications{}
	tests := []struct {
		name          string
		headerResults []executor.RequestHeaderPolicyResult
		bodyResults   []executor.RequestPolicyResult
		status        int
		wantPolicy    string
		wantVersion   string
		wantPhase     string
	}{
		{
			name: "header-phase denial",
			headerResults: []executor.RequestHeaderPolicyResult{
				{PolicyName: "analytics", PolicyVersion: "v1.0.0", Action: allow},
				{PolicyName: "skipped", PolicyVersion: "v1", Skipped: true},
				{PolicyName: "api-key-auth", PolicyVersion: "v1.2.0", Action: deny(401, nil)},
			},
			status:      401,
			wantPolicy:  "api-key-auth",
			wantVersion: "v1.2.0",
			wantPhase:   DeniedPhaseRequestHeaders,
		},
		{
			name: "body-phase denial wins over header results",
			headerResults: []executor.RequestHeaderPolicyResult{
				{PolicyName: "jwt-auth", PolicyVersion: "v0.9.0", Action: allow},
			},
			bodyResults: []executor.RequestPolicyResult{
				{PolicyName: "analytics", PolicyVersion: "v1.0.0", Action: policy.UpstreamRequestModifications{}},
				{PolicyName: "content-length-guardrail", PolicyVersion: "v0.1.0", Action: deny(422, nil)},
			},
			status:      422,
			wantPolicy:  "content-length-guardrail",
			wantVersion: "v0.1.0",
			wantPhase:   DeniedPhaseRequestBody,
		},
		{
			name: "policy answered (2xx) is not a denial",
			headerResults: []executor.RequestHeaderPolicyResult{
				{PolicyName: "agent-card", PolicyVersion: "v1", Action: deny(200, nil)},
			},
			status: 200,
		},
		{
			name:   "no recorded result stamps no denied-by",
			status: 403,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec := shortCircuitCtx(&policy.SharedContext{})
			out := collectShortCircuitAnalytics(ec, tt.headerResults, tt.bodyResults, deny(tt.status, nil))
			if tt.wantPolicy == "" {
				assert.NotContains(t, out, DeniedByPolicyKey)
				assert.NotContains(t, out, DeniedByPolicyVersionKey)
				assert.NotContains(t, out, DeniedPhaseKey)
				return
			}
			assert.Equal(t, constants.TerminalReasonPolicyDenied, out[TerminalReasonKey])
			assert.Equal(t, tt.wantPolicy, out[DeniedByPolicyKey])
			assert.Equal(t, tt.wantVersion, out[DeniedByPolicyVersionKey])
			assert.Equal(t, tt.wantPhase, out[DeniedPhaseKey])
		})
	}
}

// An mcp-authz style denial: the caller authenticated (mcp-auth) but failed
// authorization. The response phases that would export identity never run, so the
// kernel must carry it, along with what earlier policies wrote to shared metadata.
func TestCollectShortCircuitAnalytics_StampsIdentityAndMetadata(t *testing.T) {
	sc := &policy.SharedContext{
		AuthContext: &policy.AuthContext{
			Authenticated: true, Authorized: false, AuthType: "mcp/oauth",
			Subject: "alice", Issuer: "https://idp", Scopes: map[string]bool{"read": true},
		},
		Metadata: map[string]interface{}{"mcp.tool": "orderPizza", "__analytics_stream_acc": []byte("x")},
	}
	ec := shortCircuitCtx(sc)
	headerResults := []executor.RequestHeaderPolicyResult{
		{PolicyName: "mcp-authz", PolicyVersion: "v1.0.0", Action: deny(403, nil)},
	}

	out := collectShortCircuitAnalytics(ec, headerResults, nil, deny(403, nil))

	assert.Equal(t, "alice", out[AuthUserIDKey])
	assert.Equal(t, "mcp/oauth", out[AuthTypeKey])
	assert.Equal(t, "https://idp", out[AuthIssuerKey])
	assert.Equal(t, "read", out[AuthScopesKey])
	assert.Equal(t, "false", out[AuthAuthorizedKey])
	assert.Equal(t, `{"mcp.tool":"orderPizza"}`, out[GenericMetadataKey])
	assert.Equal(t, "mcp-authz", out[DeniedByPolicyKey])
}

func TestCollectShortCircuitAnalytics_UnauthenticatedStampsNoIdentity(t *testing.T) {
	for _, auth := range []*policy.AuthContext{nil, {Authenticated: false, Subject: "x"}} {
		ec := shortCircuitCtx(&policy.SharedContext{AuthContext: auth})
		out := collectShortCircuitAnalytics(ec, nil, nil, deny(401, nil))
		for _, k := range []string{AuthUserIDKey, AuthTypeKey, AuthIssuerKey, AuthCredentialIDKey,
			AuthTokenIDKey, AuthAudienceKey, AuthScopesKey, AuthPropertiesKey, AuthAuthorizedKey, GenericMetadataKey} {
			assert.NotContains(t, out, k)
		}
	}
}

func TestCollectShortCircuitAnalytics_NilSharedContextIsSafe(t *testing.T) {
	ec := &PolicyExecutionContext{analyticsMetadata: map[string]interface{}{}}
	out := collectShortCircuitAnalytics(ec, nil, nil, deny(403, nil))
	assert.Equal(t, constants.TerminalReasonPolicyDenied, out[TerminalReasonKey])
	assert.NotContains(t, out, AuthUserIDKey)
}

// Values a policy contributed always win over the kernel's stamps.
func TestCollectShortCircuitAnalytics_DoesNotOverwritePolicyKeys(t *testing.T) {
	sc := &policy.SharedContext{
		AuthContext: &policy.AuthContext{Authenticated: true, Subject: "from-context", AuthType: "jwt"},
		Metadata:    map[string]interface{}{"k": "from-context"},
	}
	ec := shortCircuitCtx(sc)
	ec.analyticsMetadata[AuthTypeKey] = "from-earlier-phase"
	headerResults := []executor.RequestHeaderPolicyResult{
		{PolicyName: "real-policy", PolicyVersion: "v2", Action: deny(403, nil)},
	}

	out := collectShortCircuitAnalytics(ec, headerResults, nil, deny(403, map[string]any{
		AuthUserIDKey:      "from-rejecting-policy",
		GenericMetadataKey: `{"k":"from-rejecting-policy"}`,
		DeniedByPolicyKey:  "self-named",
	}))

	assert.Equal(t, "from-rejecting-policy", out[AuthUserIDKey])
	assert.Equal(t, "from-earlier-phase", out[AuthTypeKey])
	assert.Equal(t, `{"k":"from-rejecting-policy"}`, out[GenericMetadataKey])
	assert.Equal(t, "self-named", out[DeniedByPolicyKey])
	assert.Equal(t, "v2", out[DeniedByPolicyVersionKey], "keys the policy did not set are still stamped")
	assert.Equal(t, DeniedPhaseRequestHeaders, out[DeniedPhaseKey])
	assert.Equal(t, "false", out[AuthAuthorizedKey])
}

// The plain request-body path (TranslateRequestBodyActions) used to aggregate its own
// short-circuit analytics and stamped no terminal reason; it now shares the collector,
// so a body-phase guardrail denial reaches the access log fully attributed.
func TestTranslateRequestActionsCore_ShortCircuit_StampsAuditFacts(t *testing.T) {
	sc := &policy.SharedContext{
		AuthContext: &policy.AuthContext{Authenticated: true, Subject: "alice", AuthType: "apikey"},
	}
	ec := shortCircuitCtx(sc)
	result := &executor.RequestExecutionResult{
		ShortCircuited: true,
		Results: []executor.RequestPolicyResult{
			{PolicyName: "analytics", PolicyVersion: "v1", Action: policy.UpstreamRequestModifications{
				AnalyticsMetadata: map[string]any{"source": "earlier"},
			}},
			{PolicyName: "content-length-guardrail", PolicyVersion: "v0.1.0", Action: deny(422, nil)},
		},
		FinalAction: deny(422, nil),
	}

	rsl, err := translateRequestActionsCore(result, ec)
	require.NoError(t, err)
	require.NotNil(t, rsl.ImmediateResp)

	fields := rsl.ImmediateResp.DynamicMetadata.GetFields()[constants.ExtProcFilterName].
		GetStructValue().GetFields()["analytics_data"].GetStructValue().GetFields()
	assert.Equal(t, "earlier", fields["source"].GetStringValue())
	assert.Equal(t, constants.TerminalReasonPolicyDenied, fields[TerminalReasonKey].GetStringValue())
	assert.Equal(t, "content-length-guardrail", fields[DeniedByPolicyKey].GetStringValue())
	assert.Equal(t, "v0.1.0", fields[DeniedByPolicyVersionKey].GetStringValue())
	assert.Equal(t, DeniedPhaseRequestBody, fields[DeniedPhaseKey].GetStringValue())
	assert.Equal(t, "alice", fields[AuthUserIDKey].GetStringValue())
	assert.Equal(t, "apikey", fields[AuthTypeKey].GetStringValue())
}
