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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/analytics/dto"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/constants"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/executor"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/resolver"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// shortCircuitCtx builds the minimal execution context the short-circuit collectors
// read: the accumulated analytics, the shared context, and the request/response
// contexts consulted for header filters.
func shortCircuitCtx(sc *policy.SharedContext) *PolicyExecutionContext {
	return &PolicyExecutionContext{
		analyticsMetadata: map[string]interface{}{},
		sharedCtx:         sc,
		requestBodyCtx:    &policy.RequestContext{SharedContext: sc},
		responseBodyCtx:   &policy.ResponseContext{SharedContext: sc},
	}
}

func deny(status int, meta map[string]any) policy.ImmediateResponse {
	return policy.ImmediateResponse{StatusCode: status, AnalyticsMetadata: meta}
}

// analyticsOf extracts the analytics_data the ALS access log will read.
func analyticsOf(t *testing.T, resp *extprocv3.ProcessingResponse) map[string]interface{} {
	t.Helper()
	require.NotNil(t, resp)
	require.NotNil(t, resp.GetImmediateResponse(), "expected an ImmediateResponse")
	return analyticsFromResponse(t, resp)
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

// authGoldenPath is the fixture shared with gateway/system-policies/analytics, whose
// tests run populateAuthAnalyticsMetadata and populateGenericMetadata against the same
// cases. A test here cannot call the collector directly: the policy-engine module does
// not depend on the system-policies module, and adding that dependency for a test would
// put it into this module's go.mod. Both modules asserting one fixture gives the same
// guarantee — neither encoding can drift without its own tests failing.
var authGoldenPath = filepath.Join("..", "..", "..", "..", "testdata", "auth_analytics_golden.json")

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
	require.NoError(t, err)
	var g authGolden
	require.NoError(t, json.Unmarshal(data, &g))
	require.NotEmpty(t, g.Auth)
	require.NotEmpty(t, g.Metadata)
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
			for _, sc := range l.Scopes {
				ac.Scopes[sc] = true
			}
		}
		head = ac
	}
	return head
}

func TestAuthAnalyticsMetadata_Golden(t *testing.T) {
	for _, tc := range loadAuthGolden(t).Auth {
		t.Run(tc.Name, func(t *testing.T) {
			var want map[string]any
			if tc.Want != nil {
				want = map[string]any{}
				for k, v := range tc.Want {
					want[k] = v
				}
			}
			assert.Equal(t, want, authAnalyticsMetadata(goldenChain(tc.Chain)))
		})
	}
}

func TestGenericMetadataAnalytics_Golden(t *testing.T) {
	for _, tc := range loadAuthGolden(t).Metadata {
		t.Run(tc.Name, func(t *testing.T) {
			assert.Equal(t, tc.Want, genericMetadataAnalytics(tc.Metadata))
		})
	}
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
	for _, auth := range []*policy.AuthContext{nil, {Authenticated: false, Subject: "x"}, {Authenticated: true}} {
		ec := shortCircuitCtx(&policy.SharedContext{AuthContext: auth})
		out := collectShortCircuitAnalytics(ec, nil, nil, deny(401, nil))
		for _, k := range append(authIdentityKeys, GenericMetadataKey) {
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

// Identity and shared metadata a policy contributed win over the kernel's stamps, and
// the identity is never assembled from two sources: if any identity key is present,
// the AuthContext tuple is not stamped at all.
func TestCollectShortCircuitAnalytics_IdentityComesFromOneSource(t *testing.T) {
	sc := &policy.SharedContext{
		AuthContext: &policy.AuthContext{Authenticated: true, Subject: "from-context", AuthType: "jwt", Issuer: "https://idp"},
		Metadata:    map[string]interface{}{"k": "from-context"},
	}

	t.Run("policy identity present: no AuthContext keys mixed in", func(t *testing.T) {
		ec := shortCircuitCtx(sc)
		ec.analyticsMetadata[AuthTypeKey] = "from-earlier-phase"
		out := collectShortCircuitAnalytics(ec, nil, nil, deny(403, map[string]any{
			AuthUserIDKey:      "from-rejecting-policy",
			GenericMetadataKey: `{"k":"from-rejecting-policy"}`,
		}))
		assert.Equal(t, "from-rejecting-policy", out[AuthUserIDKey])
		assert.Equal(t, "from-earlier-phase", out[AuthTypeKey])
		assert.NotContains(t, out, AuthIssuerKey, "no key may come from the AuthContext once a policy supplied identity")
		assert.NotContains(t, out, AuthAuthorizedKey)
		assert.Equal(t, `{"k":"from-rejecting-policy"}`, out[GenericMetadataKey])
	})

	t.Run("no policy identity: the whole AuthContext tuple", func(t *testing.T) {
		out := collectShortCircuitAnalytics(shortCircuitCtx(sc), nil, nil, deny(403, nil))
		assert.Equal(t, "from-context", out[AuthUserIDKey])
		assert.Equal(t, "jwt", out[AuthTypeKey])
		assert.Equal(t, "https://idp", out[AuthIssuerKey])
		assert.Equal(t, "false", out[AuthAuthorizedKey])
		assert.Equal(t, `{"k":"from-context"}`, out[GenericMetadataKey])
	})
}

// The denied-by keys are engine facts. Neither an earlier policy nor the rejecting
// policy can name a different denier, none survive on an outcome that is not a
// denial, and a policy cannot assert any of them on a pass-through.
func TestCollectShortCircuitAnalytics_DeniedByCannotBeForged(t *testing.T) {
	forged := map[string]any{
		DeniedByPolicyKey:        "innocent-policy",
		DeniedByPolicyVersionKey: "v9",
		DeniedPhaseKey:           "response_body",
		TerminalReasonKey:        "upstream_response",
	}
	headerResults := []executor.RequestHeaderPolicyResult{
		{PolicyName: "earlier", PolicyVersion: "v1", Action: policy.UpstreamRequestHeaderModifications{AnalyticsMetadata: forged}},
		{PolicyName: "real-denier", PolicyVersion: "v2", Action: deny(403, nil)},
	}

	t.Run("earlier and rejecting policies forging a denial", func(t *testing.T) {
		ec := shortCircuitCtx(&policy.SharedContext{})
		ec.analyticsMetadata[DeniedByPolicyKey] = "from-earlier-phase"
		out := collectShortCircuitAnalytics(ec, headerResults, nil, deny(403, forged))
		assert.Equal(t, constants.TerminalReasonPolicyDenied, out[TerminalReasonKey])
		assert.Equal(t, "real-denier", out[DeniedByPolicyKey])
		assert.Equal(t, "v2", out[DeniedByPolicyVersionKey])
		assert.Equal(t, DeniedPhaseRequestHeaders, out[DeniedPhaseKey])

		built, err := buildAnalyticsStruct(out, ec)
		require.NoError(t, err)
		assert.Equal(t, "real-denier", built.Fields[DeniedByPolicyKey].GetStringValue())
		assert.Equal(t, constants.TerminalReasonPolicyDenied, built.Fields[TerminalReasonKey].GetStringValue())
		assert.NotContains(t, built.Fields, engineAttributionMarkerKey, "the marker is never emitted")
	})

	t.Run("policy answered: forged denied-by is dropped", func(t *testing.T) {
		answered := []executor.RequestHeaderPolicyResult{
			{PolicyName: "agent-card", PolicyVersion: "v1", Action: deny(200, nil)},
		}
		out := collectShortCircuitAnalytics(shortCircuitCtx(&policy.SharedContext{}), answered, nil, deny(200, forged))
		assert.Equal(t, constants.TerminalReasonPolicyAnswered, out[TerminalReasonKey])
		assert.NotContains(t, out, DeniedByPolicyKey)
		assert.NotContains(t, out, DeniedByPolicyVersionKey)
		assert.NotContains(t, out, DeniedPhaseKey)
	})

	t.Run("pass-through: a policy cannot assert engine attribution at all", func(t *testing.T) {
		built, err := buildAnalyticsStruct(map[string]any{
			DeniedByPolicyKey: "x", DeniedByPolicyVersionKey: "v", DeniedPhaseKey: "request_headers",
			TerminalReasonKey: constants.TerminalReasonPolicyDenied, "other": "kept",
			// copying the marker's name does not help: its value is not the kernel's type
			engineAttributionMarkerKey: "forged",
		}, nil)
		require.NoError(t, err)
		for _, k := range []string{DeniedByPolicyKey, DeniedByPolicyVersionKey, DeniedPhaseKey, TerminalReasonKey, engineAttributionMarkerKey} {
			assert.NotContains(t, built.Fields, k)
		}
		assert.Equal(t, "kept", built.Fields["other"].GetStringValue())
	})
}

// api-key-auth (v1.2.1) authenticates without a subject; its layer is still stamped.
func TestCollectShortCircuitAnalytics_APIKeyIdentityWithoutSubject(t *testing.T) {
	sc := &policy.SharedContext{AuthContext: &policy.AuthContext{
		Authenticated: true, AuthType: "apikey", TokenId: "fp",
		Properties: map[string]string{"ApplicationID": "app-1"},
	}}
	out := collectShortCircuitAnalytics(shortCircuitCtx(sc), nil, nil, deny(429, nil))
	assert.NotContains(t, out, AuthUserIDKey)
	assert.Equal(t, "apikey", out[AuthTypeKey])
	assert.Equal(t, "fp", out[AuthTokenIDKey])
	assert.Equal(t, `{"ApplicationID":"app-1"}`, out[AuthPropertiesKey])
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
	fields := analyticsOf(t, rsl.ImmediateResp)
	assert.Equal(t, "earlier", fields["source"])
	assert.Equal(t, constants.TerminalReasonPolicyDenied, fields[TerminalReasonKey])
	assert.Equal(t, "content-length-guardrail", fields[DeniedByPolicyKey])
	assert.Equal(t, "v0.1.0", fields[DeniedByPolicyVersionKey])
	assert.Equal(t, DeniedPhaseRequestBody, fields[DeniedPhaseKey])
	assert.Equal(t, "alice", fields[AuthUserIDKey])
	assert.Equal(t, "apikey", fields[AuthTypeKey])
}

// requestHeaderShortCircuitResponse end to end: the header-phase ImmediateResponse
// carries attribution and identity onto the wire.
func TestTranslateRequestHeaderActions_ShortCircuit_StampsAuditFacts(t *testing.T) {
	sc := &policy.SharedContext{AuthContext: &policy.AuthContext{
		Authenticated: true, Subject: "alice", AuthType: "mcp/oauth",
	}}
	result := &executor.RequestHeaderExecutionResult{
		ShortCircuited: true,
		Results: []executor.RequestHeaderPolicyResult{
			{PolicyName: "mcp-authz", PolicyVersion: "v1.0.0", Action: deny(403, nil)},
		},
		FinalAction: deny(403, nil),
	}
	resp, err := TranslateRequestHeaderActions(result, nil, shortCircuitCtx(sc))
	require.NoError(t, err)
	fields := analyticsOf(t, resp)
	assert.Equal(t, "mcp-authz", fields[DeniedByPolicyKey])
	assert.Equal(t, DeniedPhaseRequestHeaders, fields[DeniedPhaseKey])
	assert.Equal(t, "alice", fields[AuthUserIDKey])
	assert.Equal(t, "false", fields[AuthAuthorizedKey])
}

// The deferred-binding path, where the chain is bound at the request-body callback and
// header and body policies run together, stamps the same facts.
func TestDeferredBinding_ShortCircuitStampsAuditFacts(t *testing.T) {
	r := &fakeOperationResolver{name: "body", reqs: resolver.RequestRequirements{Body: resolver.BodyBuffered}, bodyField: "method"}
	f := newResolutionFixture(t, r)
	f.route("POST|/rpc|example.com", resolver.RouteResolution{ResolverName: "body"})
	f.operationChain("SendMessage",
		&analyticsPolicy{headerMetadata: map[string]any{"auth_subject": "user-7"}},
		&analyticsPolicy{rejectStatus: 429},
	)

	execCtx := f.bindPending(t, "POST|/rpc|example.com")
	execCtx.sharedCtx.AuthContext = &policy.AuthContext{Authenticated: true, Subject: "user-7", AuthType: "jwt"}
	execCtx.sharedCtx.Metadata = map[string]interface{}{"a2a.task": "t-1"}
	resp, err := execCtx.processRequestBody(context.Background(),
		&extprocv3.HttpBody{Body: []byte(`{"method":"SendMessage"}`), EndOfStream: true})
	require.NoError(t, err)

	fields := analyticsOf(t, resp)
	assert.Equal(t, "user-7", fields["auth_subject"], "earlier analytics are kept")
	assert.Equal(t, constants.TerminalReasonPolicyDenied, fields[TerminalReasonKey])
	assert.Equal(t, "fake", fields[DeniedByPolicyKey], "the test chain names every policy spec \"fake\"")
	assert.Equal(t, "v1", fields[DeniedByPolicyVersionKey])
	assert.Equal(t, DeniedPhaseRequestBody, fields[DeniedPhaseKey])
	assert.Equal(t, "user-7", fields[AuthUserIDKey])
	assert.Equal(t, "jwt", fields[AuthTypeKey])
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(fields[GenericMetadataKey].(string)), &meta))
	assert.Equal(t, "t-1", meta["a2a.task"], "shared metadata written before the denial is carried")
}

// requestPhaseAnalytics is what earlier phases left in execCtx.analyticsMetadata.
func requestPhaseAnalytics() map[string]interface{} {
	return map[string]interface{}{
		"request_headers":        `{"x-request-id":"r-1"}`,
		"mcp_request_properties": `{"jsonRpcMethod":"tools/call","capabilityName":"orderPizza"}`,
	}
}

// Response-phase denials (e.g. a response guardrail) keep every analytics fact collected
// so far — their ImmediateResponse's analytics replace the earlier phases' on the access
// log — and are attributed like request-phase denials.
func TestResponseShortCircuit_StampsAuditFactsAndKeepsEarlierAnalytics(t *testing.T) {
	sc := &policy.SharedContext{
		AuthContext: &policy.AuthContext{Authenticated: true, Subject: "alice", AuthType: "jwt"},
		Metadata:    map[string]interface{}{"mcp.tool": "orderPizza"},
	}

	t.Run("response-header phase", func(t *testing.T) {
		ec := shortCircuitCtx(sc)
		ec.analyticsMetadata = requestPhaseAnalytics()
		result := &executor.ResponseHeaderExecutionResult{
			ShortCircuited: true,
			Results: []executor.ResponseHeaderPolicyResult{
				{PolicyName: "analytics", PolicyVersion: "v1", Action: policy.DownstreamResponseHeaderModifications{
					AnalyticsMetadata: map[string]any{"response_content_type": "application/json"},
				}},
				{PolicyName: "header-guard", PolicyVersion: "v0.2.0", Action: deny(502, map[string]any{"reason": "blocked"})},
			},
			FinalAction: deny(502, map[string]any{"reason": "blocked"}),
		}
		resp, err := TranslateResponseHeaderActions(result, ec)
		require.NoError(t, err)
		fields := analyticsOf(t, resp)
		assert.Equal(t, `{"x-request-id":"r-1"}`, fields["request_headers"])
		assert.Contains(t, fields, "mcp_request_properties")
		assert.Equal(t, "application/json", fields["response_content_type"])
		assert.Equal(t, "blocked", fields["reason"])
		assert.Equal(t, constants.TerminalReasonPolicyDenied, fields[TerminalReasonKey])
		assert.Equal(t, "header-guard", fields[DeniedByPolicyKey])
		assert.Equal(t, "v0.2.0", fields[DeniedByPolicyVersionKey])
		assert.Equal(t, DeniedPhaseResponseHeaders, fields[DeniedPhaseKey])
		assert.Equal(t, "alice", fields[AuthUserIDKey])
		assert.Equal(t, `{"mcp.tool":"orderPizza"}`, fields[GenericMetadataKey])
	})

	t.Run("response-body phase keeps the response-header phase identity", func(t *testing.T) {
		ec := shortCircuitCtx(sc)
		ec.analyticsMetadata = requestPhaseAnalytics()
		// The analytics system policy already exported identity at response headers.
		ec.analyticsMetadata[AuthUserIDKey] = "collector-subject"
		ec.analyticsMetadata[AuthTypeKey] = "jwt"
		result := &executor.ResponseExecutionResult{
			ShortCircuited: true,
			Results: []executor.ResponsePolicyResult{
				{PolicyName: "pii-guardrail", PolicyVersion: "v1.1.0", Action: deny(446, nil)},
			},
			FinalAction: deny(446, nil),
		}
		_, _, _, _, imm, err := translateResponseActionsCore(result, ec)
		require.NoError(t, err)
		fields := analyticsOf(t, imm)
		assert.Contains(t, fields, "request_headers")
		assert.Equal(t, "pii-guardrail", fields[DeniedByPolicyKey])
		assert.Equal(t, DeniedPhaseResponseBody, fields[DeniedPhaseKey])
		assert.Equal(t, "collector-subject", fields[AuthUserIDKey], "identity from one source: the collector's")
		assert.NotContains(t, fields, AuthAuthorizedKey)
	})

	t.Run("merged bodyless response: header results count too", func(t *testing.T) {
		ec := shortCircuitCtx(sc)
		ec.analyticsMetadata = requestPhaseAnalytics()
		headerResult := &executor.ResponseHeaderExecutionResult{
			Results: []executor.ResponseHeaderPolicyResult{
				{PolicyName: "analytics", PolicyVersion: "v1", Action: policy.DownstreamResponseHeaderModifications{
					AnalyticsMetadata: map[string]any{"from_header_pass": "yes"},
				}},
			},
		}
		bodyResult := &executor.ResponseExecutionResult{
			ShortCircuited: true,
			Results: []executor.ResponsePolicyResult{
				{PolicyName: "body-guard", PolicyVersion: "v3", Action: deny(500, nil)},
			},
			FinalAction: deny(500, nil),
		}
		resp, err := TranslateResponseHeaderActionsWithBodyMerge(headerResult, bodyResult, ec)
		require.NoError(t, err)
		fields := analyticsOf(t, resp)
		assert.Equal(t, "yes", fields["from_header_pass"])
		assert.Contains(t, fields, "request_headers")
		assert.Equal(t, "body-guard", fields[DeniedByPolicyKey])
		assert.Equal(t, DeniedPhaseResponseBody, fields[DeniedPhaseKey])
		assert.Equal(t, "alice", fields[AuthUserIDKey])
	})
}
