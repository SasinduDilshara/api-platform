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
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/analytics"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/config"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/constants"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/executor"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// These tests run the whole traffic-log pipeline on real data: the kernel builds the
// ext_proc response, its dynamic metadata becomes the ALS entry's filter metadata (as
// Envoy echoes it), and analytics.Process runs prepareAnalyticEvent and the Log
// publisher into a file sink. A change to any key or Go type along that path makes a
// block disappear here, not only in a hand-built dto.Event.

// alsEntry wraps ext_proc analytics_data the way Envoy hands it to the ALS server.
func alsEntry(analyticsData *structpb.Struct, method corev3.RequestMethod, path string, status uint32) *accesslogv3.HTTPAccessLogEntry {
	return &accesslogv3.HTTPAccessLogEntry{
		CommonProperties: &accesslogv3.AccessLogCommon{
			StartTime: timestamppb.New(time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)),
			StreamId:  "stream-1",
			Metadata: &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
				constants.ExtProcFilterName: {Fields: map[string]*structpb.Value{
					"analytics_data": structpb.NewStructValue(analyticsData),
				}},
			}},
			DownstreamRemoteAddress: &corev3.Address{Address: &corev3.Address_SocketAddress{
				SocketAddress: &corev3.SocketAddress{Address: "10.0.0.7"},
			}},
		},
		Request:  &accesslogv3.HTTPRequestProperties{RequestMethod: method, Path: path, Authority: "gw.example.com", UserAgent: "agent/1.0"},
		Response: &accesslogv3.HTTPResponseProperties{ResponseCode: wrapperspb.UInt32(status)},
	}
}

// analyticsDataOf returns the analytics_data struct of a kernel ext_proc response.
func analyticsDataOf(t *testing.T, resp *extprocv3.ProcessingResponse) *structpb.Struct {
	t.Helper()
	require.NotNil(t, resp)
	ns := resp.DynamicMetadata.GetFields()[constants.ExtProcFilterName].GetStructValue()
	data := ns.GetFields()["analytics_data"].GetStructValue()
	require.NotNil(t, data)
	return data
}

// publishThroughPipeline runs entry through analytics.Process with traffic logging on
// a file sink, and returns the single emitted line.
func publishThroughPipeline(t *testing.T, entry *accesslogv3.HTTPAccessLogEntry) map[string]interface{} {
	t.Helper()
	path := filepath.Join(t.TempDir(), "traffic.log")
	cfg := &config.Config{TrafficLogging: config.TrafficLoggingConfig{
		Enabled:     true,
		Outputs:     []string{config.TrafficLogSinkFile},
		File:        config.TrafficLogFileConfig{Path: path, MaxSizeMB: 10},
		AuditClaims: []string{"act"},
		GatewayID:   "gw-e2e",
	}}
	a := analytics.NewAnalytics(cfg)
	a.Process(entry)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, a.Close(ctx))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	require.Len(t, lines, 1, "expected exactly one traffic-log line, got %q", string(data))
	var line map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &line))
	return line
}

func objOf(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	m, ok := v.(map[string]interface{})
	require.True(t, ok, "expected object, got %T (%v)", v, v)
	return m
}

// An mcp-authz denial of tools/call: the analytics policy ran first at request
// headers (session and JSON-RPC facts), mcp-auth authenticated the caller with a
// delegation claim, mcp-authz denied. The line names the caller, the agent acting for
// them, the tool, and the denying policy.
func TestTrafficLogE2E_MCPToolCallDenial(t *testing.T) {
	sc := &policy.SharedContext{
		APIKind: policy.APIKindMCP, APIName: "pizza-mcp", APIId: "api-1",
		AuthContext: &policy.AuthContext{
			Authenticated: true, Authorized: false, AuthType: "mcp/oauth", Subject: "alice",
			Issuer: "https://idp", Scopes: map[string]bool{"menu:read": true},
			Properties: map[string]string{"act": `{"sub":"agent-1"}`, "email": "alice@example.com"},
		},
	}
	ec := shortCircuitCtx(sc)
	result := &executor.RequestHeaderExecutionResult{
		ShortCircuited: true,
		Results: []executor.RequestHeaderPolicyResult{
			{PolicyName: "analytics", PolicyVersion: "v1.0.0", Action: policy.UpstreamRequestHeaderModifications{
				AnalyticsMetadata: map[string]any{
					"mcp_session_id":         "sess-1",
					"mcp_request_properties": `{"jsonRpcMethod":"tools/call","jsonRpcId":"7","capability":"TOOL","capabilityName":"orderPizza"}`,
				},
			}},
			{PolicyName: "mcp-authz", PolicyVersion: "v1.0.0", Action: deny(403, nil)},
		},
		FinalAction: deny(403, nil),
	}
	resp, err := TranslateRequestHeaderActions(result, nil, ec)
	require.NoError(t, err)

	line := publishThroughPipeline(t, alsEntry(analyticsDataOf(t, resp), corev3.RequestMethod_POST, "/mcp", 403))

	assert.Equal(t, float64(403), line["status"])
	assert.Equal(t, map[string]interface{}{"id": "gw-e2e"}, objOf(t, line["gateway"]))
	assert.NotEmpty(t, line["eventId"])
	assert.Equal(t, float64(1), line["seq"])

	auth := objOf(t, line["auth"])
	assert.Equal(t, "alice", auth["subject"])
	assert.Equal(t, "mcp/oauth", auth["type"])
	assert.Equal(t, false, auth["authorized"])
	assert.Equal(t, []interface{}{"menu:read"}, auth["scopes"])
	assert.Equal(t, map[string]interface{}{"act": map[string]interface{}{"sub": "agent-1"}}, auth["claims"],
		"only the default audit claim; email is not logged")

	assert.Equal(t, map[string]interface{}{
		"method": "tools/call", "id": "7", "capability": "TOOL", "name": "orderPizza", "sessionId": "sess-1",
	}, objOf(t, line["mcp"]))

	assert.Equal(t, map[string]interface{}{
		"terminalReason": constants.TerminalReasonPolicyDenied,
		"deniedBy":       map[string]interface{}{"policy": "mcp-authz", "version": "v1.0.0", "phase": "request_headers"},
	}, objOf(t, line["decision"]))
}

// A non-deferred request-body denial of an A2A call. The body path now carries the
// terminal reason, so the A2A dimensions attribute the failure to the policy layer.
func TestTrafficLogE2E_A2ABodyPhaseDenialIsPolicyFailure(t *testing.T) {
	sc := &policy.SharedContext{APIKind: policy.APIKindAgent, APIName: "weather-agent", APIId: "agent-1", ResolvedOperation: "SendMessage"}
	ec := shortCircuitCtx(sc)
	result := &executor.RequestExecutionResult{
		ShortCircuited: true,
		Results: []executor.RequestPolicyResult{
			{PolicyName: "prompt-guard", PolicyVersion: "v0.3.0", Action: deny(422, nil)},
		},
		FinalAction: deny(422, nil),
	}
	rsl, err := translateRequestActionsCore(result, ec)
	require.NoError(t, err)

	line := publishThroughPipeline(t, alsEntry(analyticsDataOf(t, rsl.ImmediateResp), corev3.RequestMethod_POST, "/agent", 422))

	a2a := objOf(t, line["a2a"])
	assert.Equal(t, analytics.A2AOutcomeFailure, a2a["outcome"])
	assert.Equal(t, analytics.A2AFailureOriginPolicy, a2a["failureOrigin"])
	decision := objOf(t, line["decision"])
	assert.Equal(t, "prompt-guard", objOf(t, decision["deniedBy"])["policy"])
	assert.Equal(t, "request_body", objOf(t, decision["deniedBy"])["phase"])
}

// A response guardrail denial keeps what earlier phases collected, including the LLM
// facts, and is attributed to the response-body phase.
func TestTrafficLogE2E_ResponseGuardrailDenial(t *testing.T) {
	sc := &policy.SharedContext{
		APIKind: policy.APIKindLlmProvider, APIName: "openai", APIId: "llm-1",
		AuthContext: &policy.AuthContext{Authenticated: true, AuthType: "apikey", TokenId: "fp-1"},
	}
	ec := shortCircuitCtx(sc)
	ec.analyticsMetadata = map[string]interface{}{
		"ai:providername":        "openai",
		"aitoken:modelid":        "gpt-4o-2024-08-06",
		"aitoken:requestmodelid": "gpt-4o",
	}
	result := &executor.ResponseExecutionResult{
		ShortCircuited: true,
		Results: []executor.ResponsePolicyResult{
			{PolicyName: "pii-guardrail", PolicyVersion: "v1.1.0", Action: deny(446, map[string]any{
				constants.GuardrailHitMetadataKey:  true,
				constants.GuardrailNameMetadataKey: "pii-guardrail",
			})},
		},
		FinalAction: deny(446, map[string]any{
			constants.GuardrailHitMetadataKey:  true,
			constants.GuardrailNameMetadataKey: "pii-guardrail",
		}),
	}
	_, _, _, _, imm, err := translateResponseActionsCore(result, ec)
	require.NoError(t, err)

	line := publishThroughPipeline(t, alsEntry(analyticsDataOf(t, imm), corev3.RequestMethod_POST, "/chat/completions", 446))

	ai := objOf(t, line["ai"])
	assert.Equal(t, "openai", ai["provider"])
	assert.Equal(t, "gpt-4o", ai["requestModel"])
	assert.Equal(t, map[string]interface{}{"hit": true, "name": "pii-guardrail"}, objOf(t, line["guardrail"]))
	auth := objOf(t, line["auth"])
	assert.Equal(t, true, auth["authenticated"])
	assert.Equal(t, "apikey", auth["type"])
	assert.Equal(t, "fp-1", auth["tokenId"])
	assert.NotContains(t, auth, "subject")
	deniedBy := objOf(t, objOf(t, line["decision"])["deniedBy"])
	assert.Equal(t, "pii-guardrail", deniedBy["policy"])
	assert.Equal(t, "response_body", deniedBy["phase"])
}

// A completed LLM call, with analytics_data as the analytics system policy emits it.
func TestTrafficLogE2E_LLMCompletion(t *testing.T) {
	data, err := structpb.NewStruct(map[string]interface{}{
		"x-wso2-api-kind":              "LlmProvider",
		"x-wso2-api-version":           "v1.0",
		"ai:providername":              "openai",
		"aitoken:modelid":              "gpt-4o-2024-08-06",
		"aitoken:requestmodelid":       "gpt-4o",
		"aitoken:prompttokencount":     "100",
		"aitoken:completiontokencount": "50",
		"aitoken:totaltokencount":      "150",
		"x-llm-cost":                   "0.00042",
		"x-wso2-auth-type":             "apikey",
		"x-wso2-auth-token-id":         "fp-1",
		"x-wso2-auth-authorized":       "false",
		// a pass-through: a policy-forged attribution must not surface
		"x-wso2-denied-by-policy": "forged",
	})
	require.NoError(t, err)
	// buildAnalyticsStruct is what every non-short-circuit phase goes through.
	built, err := buildAnalyticsStruct(data.AsMap(), nil)
	require.NoError(t, err)

	line := publishThroughPipeline(t, alsEntry(built, corev3.RequestMethod_POST, "/chat/completions", 200))

	assert.Equal(t, map[string]interface{}{
		"provider": "openai", "providerVersion": "v1.0", "model": "gpt-4o-2024-08-06", "requestModel": "gpt-4o",
		"promptTokens": float64(100), "completionTokens": float64(50), "totalTokens": float64(150), "cost": 0.00042,
	}, objOf(t, line["ai"]))
	assert.Equal(t, "apikey", objOf(t, line["auth"])["type"])
	assert.NotContains(t, line, "decision")
}
