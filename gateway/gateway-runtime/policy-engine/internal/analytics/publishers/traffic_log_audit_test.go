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

package publishers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/analytics/dto"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/config"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/constants"
)

// auditLine runs toTrafficLogEvent with no flow toggles and returns the line as JSON
// and as a decoded map.
func auditLine(t *testing.T, event *dto.Event) (string, map[string]interface{}) {
	t.Helper()
	return auditLineWithClaims(t, event, map[string]bool{"act": true}) // the default audit_claims
}

func auditLineWithClaims(t *testing.T, event *dto.Event, claims map[string]bool) (string, map[string]interface{}) {
	t.Helper()
	l := &Log{auditClaims: claims}
	data, err := json.Marshal(l.toTrafficLogEvent(event, &dto.TrafficLogDirective{}))
	require.NoError(t, err)
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &m))
	return string(data), m
}

func obj(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	m, ok := v.(map[string]interface{})
	require.True(t, ok, "expected object, got %T (%v)", v, v)
	return m
}

func TestToTrafficLogEvent_AuditBlocks(t *testing.T) {
	isErrFalse := false
	tests := []struct {
		name   string
		mutate func(e *dto.Event)
		check  func(t *testing.T, line map[string]interface{})
	}{
		{
			name: "mcp tools/call",
			mutate: func(e *dto.Event) {
				e.Properties[mcpAnalyticsProperty] = map[string]interface{}{
					"sessionId":      "sess-1",
					"jsonRpcMethod":  "tools/call",
					"jsonRpcId":      "7",
					"capability":     "TOOL",
					"capabilityName": "orderPizza",
					"clientInfo": map[string]interface{}{
						"requestedProtocolVersion": "2025-06-18", "name": "inspector", "version": "1.2",
					},
					"isError":    false,
					"errorCode":  -32601, // int, as prepareAnalyticEvent stores mcpErrorCode
					"resultType": "complete",
					"serverInfo": map[string]interface{}{"name": "pizza", "version": "0.1"},
					// keys outside the block are not carried
					"requestStateHash": "abc",
				}
			},
			check: func(t *testing.T, line map[string]interface{}) {
				mcp := obj(t, line["mcp"])
				assert.Equal(t, map[string]interface{}{
					"method":     "tools/call",
					"id":         "7",
					"capability": "TOOL",
					"name":       "orderPizza",
					"sessionId":  "sess-1",
					"clientInfo": map[string]interface{}{
						"requestedProtocolVersion": "2025-06-18", "name": "inspector", "version": "1.2",
					},
					"isError":    isErrFalse,
					"errorCode":  float64(-32601),
					"resultType": "complete",
					"serverInfo": map[string]interface{}{"name": "pizza", "version": "0.1"},
				}, mcp)
			},
		},
		{
			name: "mcp errorCode raw string",
			mutate: func(e *dto.Event) {
				e.Properties[mcpAnalyticsProperty] = map[string]interface{}{
					"jsonRpcMethod": "tools/call", "errorCode": "E_DENIED",
				}
			},
			check: func(t *testing.T, line map[string]interface{}) {
				mcp := obj(t, line["mcp"])
				assert.Equal(t, "E_DENIED", mcp["errorCode"])
				assert.NotContains(t, mcp, "isError")
			},
		},
		{
			name: "mcp resources/read",
			mutate: func(e *dto.Event) {
				e.Properties[mcpAnalyticsProperty] = map[string]interface{}{
					"jsonRpcMethod": "resources/read", "jsonRpcId": "3", "capability": "RESOURCE",
					"resourceUri": "file:///menu.json",
				}
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.Equal(t, map[string]interface{}{
					"method": "resources/read", "id": "3", "capability": "RESOURCE",
					"resourceUri": "file:///menu.json",
				}, obj(t, line["mcp"]))
			},
		},
		{
			name: "llm",
			mutate: func(e *dto.Event) {
				hour := 13
				e.Properties[aiMetadataProperty] = dto.AIMetadata{
					Model: "gpt-4o-2024-08-06", VendorName: "openai", VendorVersion: "v1.0", LLMCost: 0.00042,
				}
				e.Properties[constants.RequestModelPropertyKey] = "gpt-4o"
				e.Properties[aiTokenUsageProperty] = dto.AITokenUsage{
					PromptToken: 100, CompletionToken: 50, TotalToken: 150, Hour: &hour,
				}
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.Equal(t, map[string]interface{}{
					"provider":         "openai",
					"providerVersion":  "v1.0",
					"model":            "gpt-4o-2024-08-06",
					"requestModel":     "gpt-4o",
					"promptTokens":     float64(100),
					"completionTokens": float64(50),
					"totalTokens":      float64(150),
					"cost":             0.00042,
				}, obj(t, line["ai"]), "hour is not carried")
			},
		},
		{
			name: "llm cost as raw string",
			mutate: func(e *dto.Event) {
				e.Properties[aiMetadataProperty] = &dto.AIMetadata{VendorName: "openai", LLMCost: "n/a"}
			},
			check: func(t *testing.T, line map[string]interface{}) {
				ai := obj(t, line["ai"])
				assert.Equal(t, "n/a", ai["cost"])
				assert.NotContains(t, ai, "promptTokens")
			},
		},
		{
			name: "token usage without aiMetadata emits no ai block",
			mutate: func(e *dto.Event) {
				e.Properties[aiTokenUsageProperty] = dto.AITokenUsage{TotalToken: 5}
				e.Properties[constants.RequestModelPropertyKey] = "gpt-4o"
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.NotContains(t, line, "ai")
			},
		},
		{
			name: "auth with nested act claim (string-encoded, as the collector stores it)",
			mutate: func(e *dto.Event) {
				e.Properties[dto.PropKeyAuthUserID] = "alice"
				e.Properties[dto.PropKeyAuthType] = "jwt"
				e.Properties[dto.PropKeyAuthIssuer] = "https://idp"
				e.Properties[dto.PropKeyAuthCredentialID] = "client-1"
				e.Properties[dto.PropKeyAuthTokenID] = "jti-1"
				e.Properties[dto.PropKeyAuthAudience] = "aud-a,aud-b"
				e.Properties[dto.PropKeyAuthScopes] = "admin read write"
				e.Properties[dto.PropKeyAuthAuthorized] = "true"
				props, _ := json.Marshal(map[string]string{
					"act":    `{"sub":"agent-1","act":{"sub":"agent-0"}}`,
					"tenant": "t1",
				})
				e.Properties[dto.PropKeyAuthProperties] = string(props)
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.Equal(t, map[string]interface{}{
					"subject":       "alice",
					"authenticated": true,
					"type":          "jwt",
					"issuer":        "https://idp",
					"clientId":      "client-1",
					"tokenId":       "jti-1",
					"audience":      []interface{}{"aud-a", "aud-b"},
					"scopes":        []interface{}{"admin", "read", "write"},
					"authorized":    true,
					"claims": map[string]interface{}{
						"act": map[string]interface{}{
							"sub": "agent-1",
							"act": map[string]interface{}{"sub": "agent-0"},
						},
					},
				}, obj(t, line["auth"]), "only the default audit claim (act) is emitted; tenant is not")
			},
		},
		{
			name: "auth with act claim already an object",
			mutate: func(e *dto.Event) {
				e.Properties[dto.PropKeyAuthUserID] = "alice"
				e.Properties[dto.PropKeyAuthProperties] = `{"act":{"sub":"agent-1","act":{"sub":"agent-0"}}}`
			},
			check: func(t *testing.T, line map[string]interface{}) {
				claims := obj(t, obj(t, line["auth"])["claims"])
				act := obj(t, claims["act"])
				assert.Equal(t, "agent-1", act["sub"])
				assert.Equal(t, "agent-0", obj(t, act["act"])["sub"])
			},
		},
		{
			name: "auth authorized false, non-JSON act string kept",
			mutate: func(e *dto.Event) {
				e.Properties[dto.PropKeyAuthUserID] = "bob"
				e.Properties[dto.PropKeyAuthAuthorized] = "false"
				e.Properties[dto.PropKeyAuthProperties] = `{"act":"agent-x"}`
			},
			check: func(t *testing.T, line map[string]interface{}) {
				auth := obj(t, line["auth"])
				assert.Equal(t, false, auth["authorized"])
				assert.Equal(t, true, auth["authenticated"])
				assert.Equal(t, "agent-x", obj(t, auth["claims"])["act"])
				assert.NotContains(t, auth, "audience")
				assert.NotContains(t, auth, "scopes")
			},
		},
		{
			name: "guardrail hit",
			mutate: func(e *dto.Event) {
				e.Properties[constants.GuardrailHitMetadataKey] = true
				e.Properties[constants.GuardrailNameMetadataKey] = "content-length-guardrail"
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.Equal(t, map[string]interface{}{"hit": true, "name": "content-length-guardrail"},
					obj(t, line["guardrail"]))
			},
		},
		{
			name: "guardrail not hit and unnamed is omitted",
			mutate: func(e *dto.Event) {
				e.Properties[constants.GuardrailHitMetadataKey] = false
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.NotContains(t, line, "guardrail")
			},
		},
		{
			name: "error and errorType",
			mutate: func(e *dto.Event) {
				e.ErrorType = string(dto.FaultCategoryTargetConnectivity)
				e.Error = &dto.Error{ErrorCode: 504, ErrorMessage: dto.TargetConnectivityConnectionTimeout}
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.Equal(t, string(dto.FaultCategoryTargetConnectivity), line["errorType"])
				assert.Equal(t, map[string]interface{}{
					"errorCode":    float64(504),
					"errorMessage": string(dto.TargetConnectivityConnectionTimeout),
				}, obj(t, line["error"]))
			},
		},
		{
			name: "a2a",
			mutate: func(e *dto.Event) {
				e.Properties[a2aAnalyticsProperty] = &dto.A2AAnalytics{
					RequestType: "operation", Operation: "SendMessage", Transport: "JSONRPC", Outcome: "SUCCESS",
				}
			},
			check: func(t *testing.T, line map[string]interface{}) {
				a2a := obj(t, line["a2a"])
				assert.Equal(t, "SendMessage", a2a["operation"])
				assert.Equal(t, "JSONRPC", a2a["transport"])
				assert.Equal(t, "SUCCESS", a2a["outcome"])
			},
		},
		{
			name: "decision",
			mutate: func(e *dto.Event) {
				e.Properties[dto.PropKeyTerminalReason] = constants.TerminalReasonPolicyDenied
				e.Properties[dto.PropKeyDeniedByPolicy] = "mcp-authz"
				e.Properties[dto.PropKeyDeniedByPolicyVersion] = "v1.0.0"
				e.Properties[dto.PropKeyDeniedPhase] = "request_headers"
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.Equal(t, map[string]interface{}{
					"terminalReason": constants.TerminalReasonPolicyDenied,
					"deniedBy": map[string]interface{}{
						"policy": "mcp-authz", "version": "v1.0.0", "phase": "request_headers",
					},
				}, obj(t, line["decision"]))
			},
		},
		{
			name: "deniedBy on a non-denial line is not emitted",
			mutate: func(e *dto.Event) {
				e.Properties[dto.PropKeyTerminalReason] = constants.TerminalReasonPolicyAnswered
				e.Properties[dto.PropKeyDeniedByPolicy] = "forged"
				e.Properties[dto.PropKeyDeniedPhase] = "request_headers"
			},
			check: func(t *testing.T, line map[string]interface{}) {
				d := obj(t, line["decision"])
				assert.Equal(t, constants.TerminalReasonPolicyAnswered, d["terminalReason"])
				assert.NotContains(t, d, "deniedBy")
			},
		},
		{
			name: "deniedBy without any terminal reason emits no decision",
			mutate: func(e *dto.Event) {
				e.Properties[dto.PropKeyDeniedByPolicy] = "forged"
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.NotContains(t, line, "decision")
			},
		},
		{
			name: "api-key identity without a subject is authenticated",
			mutate: func(e *dto.Event) {
				e.Properties[dto.PropKeyAuthType] = "apikey"
				e.Properties[dto.PropKeyAuthTokenID] = "fp"
				e.Properties[dto.PropKeyAuthAuthorized] = "false"
				e.Properties[dto.PropKeyAuthProperties] = `{"ApplicationID":"app-1","ApplicationName":"orders"}`
			},
			check: func(t *testing.T, line map[string]interface{}) {
				assert.Equal(t, map[string]interface{}{
					"authenticated": true, "type": "apikey", "tokenId": "fp", "authorized": false,
				}, obj(t, line["auth"]), "no subject invented; application claims not listed in audit_claims")
			},
		},
		{
			name: "malformed auth properties yield no claims but keep identity",
			mutate: func(e *dto.Event) {
				e.Properties[dto.PropKeyAuthUserID] = "alice"
				e.Properties[dto.PropKeyAuthProperties] = `{"act":`
			},
			check: func(t *testing.T, line map[string]interface{}) {
				auth := obj(t, line["auth"])
				assert.Equal(t, "alice", auth["subject"])
				assert.NotContains(t, auth, "claims")
			},
		},
		{
			name: "decision with terminal reason only",
			mutate: func(e *dto.Event) {
				e.Properties[dto.PropKeyTerminalReason] = constants.TerminalReasonResolutionFailed
			},
			check: func(t *testing.T, line map[string]interface{}) {
				d := obj(t, line["decision"])
				assert.Equal(t, constants.TerminalReasonResolutionFailed, d["terminalReason"])
				assert.NotContains(t, d, "deniedBy")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := createBaseEvent()
			tt.mutate(e)
			_, line := auditLine(t, e)
			tt.check(t, line)
		})
	}
}

// An event carrying none of the audit facts — including the properties
// prepareAnalyticEvent always sets — serializes byte-for-byte as before the change.
func TestToTrafficLogEvent_NoAuditFactsIsUnchanged(t *testing.T) {
	e := createBaseEvent()
	e.RequestTimestamp = time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.UTC)
	e.Properties["userName"] = "UNKNOWN"
	e.Properties["commonName"] = "N/A"
	e.Properties["apiContext"] = "/test"
	e.Properties["responseContentType"] = "application/json"
	e.Properties["responseSize"] = uint64(12)
	e.Properties["requestSize"] = uint64(0)
	e.Properties[constants.RequestPathPropertyKey] = "/test/resource"

	got, _ := auditLine(t, e)

	want := `{"component":"pol","timestamp":"2026-01-02T03:04:05.006Z","correlationId":"corr-123",` +
		`"status":200,"api":{"id":"api-123","name":"test-api","version":"v1.0","context":"/test",` +
		`"kind":"Rest","projectId":"project-123"},"operation":{"method":"GET","path":"/resource"},` +
		`"client":{"ip":"192.168.1.1","userAgent":"test-agent"},"latencies":{"durationUs":250000,` +
		`"requestMediationLatencyUs":50000,"responseMediationLatencyUs":30000,"backendLatencyUs":40000}}`
	assert.Equal(t, want, got)
}

func publishLines(t *testing.T, cfg *config.TrafficLoggingConfig, events ...*dto.Event) []map[string]interface{} {
	t.Helper()
	l, read := newLogToFile(t, cfg)
	for _, e := range events {
		l.Publish(e)
	}
	var lines []map[string]interface{}
	for _, raw := range strings.Split(strings.TrimRight(read(), "\n"), "\n") {
		lines = append(lines, decodeLine(t, raw))
	}
	return lines
}

func TestLog_Publish_EventIDAndSeq(t *testing.T) {
	lines := publishLines(t, &config.TrafficLoggingConfig{Enabled: true},
		createBaseEvent(), createBaseEvent(), createBaseEvent())
	require.Len(t, lines, 3)

	seen := map[string]bool{}
	for i, line := range lines {
		id, ok := line["eventId"].(string)
		require.True(t, ok, "eventId must be present")
		parsed, err := uuid.Parse(id)
		require.NoError(t, err)
		assert.Equal(t, uuid.Version(7), parsed.Version(), "eventId must be a UUIDv7")
		assert.False(t, seen[id], "eventId must be unique")
		seen[id] = true
		assert.Equal(t, float64(i+1), line["seq"], "seq starts at 1 and increments by one")
	}
}

// Concurrent Publish calls (concurrent ALS streams) never share a seq or an eventId.
// Run with -race.
func TestLog_Publish_SeqConcurrent(t *testing.T) {
	l, err := NewLog(&config.TrafficLoggingConfig{Enabled: true, Outputs: []string{config.TrafficLogSinkStdout}})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "out.log")
	f, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	useWriterSink(l, f)

	const n = 64
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			e := createBaseEvent()
			e.API.APIName = fmt.Sprintf("api-%d", i)
			l.Publish(e)
		}(i)
	}
	wg.Wait()
	require.NoError(t, f.Sync())
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	seqs := map[float64]bool{}
	ids := map[string]bool{}
	for _, raw := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		line := decodeLine(t, raw)
		seq := line["seq"].(float64)
		assert.False(t, seqs[seq], "duplicate seq %v", seq)
		seqs[seq] = true
		ids[line["eventId"].(string)] = true
	}
	require.Len(t, seqs, n)
	require.Len(t, ids, n)
	for i := 1; i <= n; i++ {
		assert.True(t, seqs[float64(i)], "seq %d missing: the counter must be gap-free", i)
	}
}

func TestLog_Publish_GatewayBlock(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.TrafficLoggingConfig
		want map[string]interface{}
	}{
		{
			name: "all set",
			cfg:  &config.TrafficLoggingConfig{Enabled: true, GatewayID: "gw-1", Organization: "org-a", Environment: "dev"},
			want: map[string]interface{}{"id": "gw-1", "organization": "org-a", "environment": "dev"},
		},
		{
			name: "partially set",
			cfg:  &config.TrafficLoggingConfig{Enabled: true, Environment: "dev"},
			want: map[string]interface{}{"environment": "dev"},
		},
		{
			name: "unset omits the block",
			cfg:  &config.TrafficLoggingConfig{Enabled: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := publishLines(t, tt.cfg, createBaseEvent())[0]
			if tt.want == nil {
				assert.NotContains(t, line, "gateway")
				return
			}
			assert.Equal(t, tt.want, obj(t, line["gateway"]))
		})
	}
}

func TestLog_Publish_ExcludeFieldsDropsAuditBlocks(t *testing.T) {
	e := createBaseEvent()
	e.Properties[dto.PropKeyAuthUserID] = "alice"
	e.Properties[mcpAnalyticsProperty] = map[string]interface{}{"jsonRpcMethod": "tools/list"}
	e.Properties[dto.PropKeyTerminalReason] = constants.TerminalReasonPolicyDenied

	kept := publishLines(t, &config.TrafficLoggingConfig{Enabled: true}, e)[0]
	assert.Contains(t, kept, "auth")
	assert.Contains(t, kept, "mcp")

	line := publishLines(t, &config.TrafficLoggingConfig{
		Enabled: true, ExcludeFields: []string{"mcp", "auth"},
	}, e)[0]
	assert.NotContains(t, line, "mcp")
	assert.NotContains(t, line, "auth")
	assert.Contains(t, line, "decision", "blocks not named stay")
	assert.Contains(t, line, "eventId")
}

// auth.claims is an allowlist (traffic_logging.audit_claims): claims are personal data.
func TestToTrafficLogEvent_AuditClaimsAllowlist(t *testing.T) {
	props, _ := json.Marshal(map[string]string{
		"act":       `{"sub":"agent-1"}`,
		"email":     "alice@example.com",
		"groups":    `["admins","ops"]`,
		"client_id": "c-1",
	})
	tests := []struct {
		name   string
		claims map[string]bool
		want   map[string]interface{}
	}{
		{
			name:   "default emits only act",
			claims: map[string]bool{"act": true},
			want:   map[string]interface{}{"act": map[string]interface{}{"sub": "agent-1"}},
		},
		{
			name:   "empty list emits none",
			claims: map[string]bool{},
		},
		{
			name:   "custom list, structured values decoded",
			claims: map[string]bool{"groups": true, "client_id": true, "absent": true},
			want: map[string]interface{}{
				"groups":    []interface{}{"admins", "ops"},
				"client_id": "c-1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := createBaseEvent()
			e.Properties[dto.PropKeyAuthUserID] = "alice"
			e.Properties[dto.PropKeyAuthProperties] = string(props)
			_, line := auditLineWithClaims(t, e, tt.claims)
			auth := obj(t, line["auth"])
			if tt.want == nil {
				assert.NotContains(t, auth, "claims")
				return
			}
			assert.Equal(t, tt.want, obj(t, auth["claims"]))
		})
	}
}

// NewLog builds the allowlist from config: trimmed, blanks ignored.
func TestNewLog_AuditClaimsFromConfig(t *testing.T) {
	l, err := NewLog(&config.TrafficLoggingConfig{AuditClaims: []string{" act ", "", "email"}})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"act": true, "email": true}, l.auditClaims)

	l, err = NewLog(&config.TrafficLoggingConfig{})
	require.NoError(t, err)
	assert.Empty(t, l.auditClaims)
}
