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

	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/constants"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/executor"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func streamCtx() *PolicyExecutionContext {
	return &PolicyExecutionContext{
		analyticsMetadata: map[string]any{},
		dynamicMetadata:   map[string]map[string]interface{}{},
	}
}

// A response guardrail that ends a stream with TerminateResponseChunk refuses the
// response after the 2xx status line was sent. The final chunk's analytics must name
// the terminating policy and the response_body_stream phase, as engine facts.
func TestStreamTermination_AttributesTerminatingPolicy(t *testing.T) {
	execCtx := streamCtx()
	result := &executor.StreamingResponseExecutionResult{
		StreamTerminated: true,
		Results: []executor.StreamingResponsePolicyResult{
			{PolicyName: "analytics", PolicyVersion: "v1", Action: policy.ForwardResponseChunk{}},
			{PolicyName: "content-length-guardrail", PolicyVersion: "v1.0.1",
				Action: policy.TerminateResponseChunk{Body: []byte(`data: {"type":"CONTENT_LENGTH_GUARDRAIL"}`)}},
		},
	}

	resp, err := TranslateStreamingResponseChunkAction(result,
		&policy.StreamBody{Chunk: []byte(`data: {"x":1}`)}, execCtx)
	require.NoError(t, err)

	got := analyticsFromResponse(t, resp)
	assert.Equal(t, constants.TerminalReasonPolicyDenied, got[TerminalReasonKey])
	assert.Equal(t, "content-length-guardrail", got[DeniedByPolicyKey])
	assert.Equal(t, "v1.0.1", got[DeniedByPolicyVersionKey])
	assert.Equal(t, DeniedPhaseResponseBodyStream, got[DeniedPhaseKey])
	_, markerLeaked := got[engineAttributionMarkerKey]
	assert.False(t, markerLeaked, "the attestation marker must never be emitted")

	// Persisted on the execution context too, so a later re-emit of the analytics
	// (stream end, access log) still carries the attribution.
	assert.Equal(t, "content-length-guardrail", execCtx.analyticsMetadata[DeniedByPolicyKey])
	assert.True(t, isEngineAttributed(execCtx.analyticsMetadata))
}

// A policy cannot forge the attribution: whatever it writes into the analytics of a
// terminated stream is overwritten by the engine's facts.
func TestStreamTermination_PolicyCannotForgeAttribution(t *testing.T) {
	execCtx := streamCtx()
	result := &executor.StreamingResponseExecutionResult{
		StreamTerminated: true,
		Results: []executor.StreamingResponsePolicyResult{
			{PolicyName: "word-count-guardrail", PolicyVersion: "v1",
				Action: policy.TerminateResponseChunk{
					Body: []byte("blocked"),
					AnalyticsMetadata: map[string]any{
						DeniedByPolicyKey:        "someone-else",
						DeniedByPolicyVersionKey: "v9",
						DeniedPhaseKey:           "request_headers",
						TerminalReasonKey:        "upstream_response",
						"isGuardrailHit":         true,
						"guardrailName":          "word-count-guardrail",
					},
				}},
		},
	}

	resp, err := TranslateStreamingResponseChunkAction(result, &policy.StreamBody{Chunk: []byte("x")}, execCtx)
	require.NoError(t, err)

	got := analyticsFromResponse(t, resp)
	assert.Equal(t, "word-count-guardrail", got[DeniedByPolicyKey])
	assert.Equal(t, "v1", got[DeniedByPolicyVersionKey])
	assert.Equal(t, DeniedPhaseResponseBodyStream, got[DeniedPhaseKey])
	assert.Equal(t, constants.TerminalReasonPolicyDenied, got[TerminalReasonKey])
	// The policy's own (non-attribution) analytics still flow through unchanged.
	assert.Equal(t, true, got["isGuardrailHit"])
	assert.Equal(t, "word-count-guardrail", got["guardrailName"])
}

// An ordinary forwarded chunk carries no attribution, and attribution keys a policy
// tries to assert on it are dropped because the engine never attested them.
func TestStreamTermination_NoAttributionWithoutTermination(t *testing.T) {
	execCtx := streamCtx()
	result := &executor.StreamingResponseExecutionResult{
		Results: []executor.StreamingResponsePolicyResult{
			{PolicyName: "llm-cost", PolicyVersion: "v1", Action: policy.ForwardResponseChunk{
				AnalyticsMetadata: map[string]any{
					"x-llm-cost":      "0.0001",
					DeniedByPolicyKey: "forged",
				},
			}},
		},
	}

	resp, err := TranslateStreamingResponseChunkAction(result, &policy.StreamBody{Chunk: []byte("ok")}, execCtx)
	require.NoError(t, err)

	got := analyticsFromResponse(t, resp)
	assert.Equal(t, "0.0001", got["x-llm-cost"])
	for _, k := range []string{TerminalReasonKey, DeniedByPolicyKey, DeniedByPolicyVersionKey, DeniedPhaseKey} {
		_, present := got[k]
		assert.False(t, present, "unattested %s must not be emitted", k)
	}
	assert.False(t, isEngineAttributed(execCtx.analyticsMetadata))
}

// StreamTerminated without a policy result carrying TerminateResponseChunk (for
// example a result list the executor did not populate) records nothing, rather than
// inventing an attribution.
func TestStreamTermination_NoResultNoAttribution(t *testing.T) {
	denied := deniedByStreamTermination([]executor.StreamingResponsePolicyResult{
		{PolicyName: "a", Skipped: true, Action: policy.TerminateResponseChunk{}},
		{PolicyName: "b", Action: policy.ForwardResponseChunk{}},
	})
	assert.False(t, denied.found)

	dest := map[string]any{}
	stampStreamTermination(dest, denied)
	assert.Empty(t, dest)

	stampStreamTermination(nil, deniedPolicy{name: "x", found: true}) // must not panic
}
