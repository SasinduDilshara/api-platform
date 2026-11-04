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
	"encoding/json"
	"log/slog"
	"maps"
	"sort"
	"strconv"
	"strings"

	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/constants"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/executor"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// Auth-context and shared-metadata analytics keys. The analytics system policy
// (gateway/system-policies/analytics, a separate Go module) stamps these in its
// response phases; the kernel stamps the same keys on a policy short-circuit, where
// those phases do not run. Mirrored as dto.PropKeyAuth* / dto.PropKeyMetadata in the
// analytics package; a kernel test asserts the spellings match, and a golden fixture
// shared with the system policy's tests (gateway/testdata/auth_analytics_golden.json)
// pins the encodings.
const (
	AuthUserIDKey       = Wso2MetadataPrefix + "user-id"
	AuthTypeKey         = Wso2MetadataPrefix + "auth-type"
	AuthIssuerKey       = Wso2MetadataPrefix + "auth-issuer"
	AuthCredentialIDKey = Wso2MetadataPrefix + "auth-credential-id"
	AuthTokenIDKey      = Wso2MetadataPrefix + "auth-token-id"
	AuthAudienceKey     = Wso2MetadataPrefix + "auth-audience"
	AuthScopesKey       = Wso2MetadataPrefix + "auth-scopes"
	AuthPropertiesKey   = Wso2MetadataPrefix + "auth-properties"
	AuthAuthorizedKey   = Wso2MetadataPrefix + "auth-authorized"
	GenericMetadataKey  = Wso2MetadataPrefix + "metadata"
)

// authIdentityKeys are the keys that together describe one caller identity.
var authIdentityKeys = []string{
	AuthUserIDKey, AuthTypeKey, AuthIssuerKey, AuthCredentialIDKey, AuthTokenIDKey,
	AuthAudienceKey, AuthScopesKey, AuthPropertiesKey, AuthAuthorizedKey,
}

// engineAttributionKeys are the facts only the engine may assert. A policy can put
// any key into its AnalyticsMetadata, so buildAnalyticsStruct drops these unless the
// map was finished by the engine itself (see engineAttributionMarkerKey).
var engineAttributionKeys = []string{
	TerminalReasonKey, DeniedByPolicyKey, DeniedByPolicyVersionKey, DeniedPhaseKey,
}

// engineAttributionMarkerKey marks an analytics map whose engine attribution keys
// were written by the kernel. Its value must be an engineAttestation, an unexported
// type no policy can construct, so a policy that copies the key name still cannot
// make its own forged attribution survive. The marker itself is never emitted.
const engineAttributionMarkerKey = "\x00kernel-engine-attribution"

type engineAttestation struct{}

// attestEngineAttribution marks dest as carrying kernel-written attribution keys.
func attestEngineAttribution(dest map[string]any) {
	dest[engineAttributionMarkerKey] = engineAttestation{}
}

// isEngineAttributed reports whether the map's attribution keys were written by the
// kernel rather than contributed by a policy.
func isEngineAttributed(data map[string]any) bool {
	_, ok := data[engineAttributionMarkerKey].(engineAttestation)
	return ok
}

// skipAnalyticsKey reports whether buildAnalyticsStruct must not emit key from data:
// the internal marker always, and the engine attribution keys unless the kernel wrote
// them.
func skipAnalyticsKey(data map[string]any, key string) bool {
	if key == engineAttributionMarkerKey {
		return true
	}
	for _, k := range engineAttributionKeys {
		if key == k {
			return !isEngineAttributed(data)
		}
	}
	return false
}

// sharedMetadataInternalKeys are the SharedContext.Metadata entries the analytics
// system policy writes for its own bookkeeping and leaves out of GenericMetadataKey
// (internalMetadataKeys in gateway/system-policies/analytics/analytics.go). Kept
// identical so a denied line and a completed line export the same set.
var sharedMetadataInternalKeys = map[string]struct{}{
	"__analytics_stream_acc": {},
	"__a2a_request_start":    {},
	"__a2a_first_event":      {},
	"__a2a_stream_scan":      {},
}

// selectAuthLayer mirrors selectAuthLayer in gateway/system-policies/analytics: the
// first authenticated layer with a subject, else the first authenticated layer that at
// least identifies its credential (a credential id or a token id) — api-key-auth, for
// one, authenticates without setting a subject. Nil when no layer qualifies.
func selectAuthLayer(authChain *policy.AuthContext) *policy.AuthContext {
	var fallback *policy.AuthContext
	for authCtx := authChain; authCtx != nil; authCtx = authCtx.Previous {
		if !authCtx.Authenticated {
			continue
		}
		if authCtx.Subject != "" {
			return authCtx
		}
		if fallback == nil && (authCtx.CredentialID != "" || authCtx.TokenId != "") {
			fallback = authCtx
		}
	}
	return fallback
}

// authAnalyticsMetadata mirrors populateAuthAnalyticsMetadata in
// gateway/system-policies/analytics/analytics.go: for the layer selectAuthLayer picks,
// it returns the auth-derived analytics keys with the same value encodings — audience
// comma-joined, scopes sorted and space-joined, Properties JSON-encoded, Authorized
// always stamped as "true"/"false", the user id only when there is a subject. Returns
// nil when no layer qualifies.
//
// The two must stay identical so the publisher parses one format regardless of
// whether the line came from a completed request or a short-circuit. TokenId is the
// token's identifier (a jti, or a SHA-256 fingerprint), never the raw token; nothing
// here is logged.
func authAnalyticsMetadata(authChain *policy.AuthContext) map[string]any {
	authCtx := selectAuthLayer(authChain)
	if authCtx == nil {
		return nil
	}
	out := map[string]any{}
	if authCtx.Subject != "" {
		out[AuthUserIDKey] = authCtx.Subject
	}
	if authCtx.AuthType != "" {
		out[AuthTypeKey] = authCtx.AuthType
	}
	if authCtx.Issuer != "" {
		out[AuthIssuerKey] = authCtx.Issuer
	}
	if authCtx.CredentialID != "" {
		out[AuthCredentialIDKey] = authCtx.CredentialID
	}
	if authCtx.TokenId != "" {
		out[AuthTokenIDKey] = authCtx.TokenId
	}
	if len(authCtx.Audience) > 0 {
		out[AuthAudienceKey] = strings.Join(authCtx.Audience, ",")
	}
	if len(authCtx.Scopes) > 0 {
		scopes := make([]string, 0, len(authCtx.Scopes))
		for name := range authCtx.Scopes {
			scopes = append(scopes, name)
		}
		sort.Strings(scopes)
		out[AuthScopesKey] = strings.Join(scopes, " ")
	}
	if len(authCtx.Properties) > 0 {
		if data, err := json.Marshal(authCtx.Properties); err == nil {
			out[AuthPropertiesKey] = string(data)
		} else {
			slog.Warn("Short-circuit analytics: failed to marshal auth properties", "error", err)
		}
	}
	out[AuthAuthorizedKey] = strconv.FormatBool(authCtx.Authorized)
	return out
}

// genericMetadataAnalytics mirrors populateGenericMetadata in
// gateway/system-policies/analytics/analytics.go: the JSON encoding of
// SharedContext.Metadata minus the analytics policy's internal bookkeeping keys.
// Returns "" when there is nothing to export or it cannot be encoded.
func genericMetadataAnalytics(sharedMetadata map[string]interface{}) string {
	if len(sharedMetadata) == 0 {
		return ""
	}
	filtered := make(map[string]interface{}, len(sharedMetadata))
	for k, v := range sharedMetadata {
		if _, internal := sharedMetadataInternalKeys[k]; internal {
			continue
		}
		filtered[k] = v
	}
	if len(filtered) == 0 {
		return ""
	}
	data, err := json.Marshal(filtered)
	if err != nil {
		slog.Warn("Short-circuit analytics: failed to marshal SharedContext.Metadata", "error", err)
		return ""
	}
	return string(data)
}

// deniedPolicy identifies the policy whose ImmediateResponse ended a chain.
type deniedPolicy struct {
	name, version, phase string
	found                bool
}

// isImmediate reports whether a policy result is the one that short-circuited.
func isImmediate(skipped bool, action any) bool {
	if skipped || action == nil {
		return false
	}
	_, ok := action.(policy.ImmediateResponse)
	return ok
}

// deniedByRequestPolicy finds the request-phase policy that returned the
// ImmediateResponse: the last body-phase result carrying one, else the last
// header-phase result. found=false when neither phase recorded one.
func deniedByRequestPolicy(
	headerResults []executor.RequestHeaderPolicyResult,
	bodyResults []executor.RequestPolicyResult,
) deniedPolicy {
	for i := len(bodyResults) - 1; i >= 0; i-- {
		if pr := bodyResults[i]; isImmediate(pr.Skipped, pr.Action) {
			return deniedPolicy{pr.PolicyName, pr.PolicyVersion, DeniedPhaseRequestBody, true}
		}
	}
	for i := len(headerResults) - 1; i >= 0; i-- {
		if pr := headerResults[i]; isImmediate(pr.Skipped, pr.Action) {
			return deniedPolicy{pr.PolicyName, pr.PolicyVersion, DeniedPhaseRequestHeaders, true}
		}
	}
	return deniedPolicy{}
}

// deniedByResponsePolicy is deniedByRequestPolicy for the response phases.
func deniedByResponsePolicy(
	headerResults []executor.ResponseHeaderPolicyResult,
	bodyResults []executor.ResponsePolicyResult,
) deniedPolicy {
	for i := len(bodyResults) - 1; i >= 0; i-- {
		if pr := bodyResults[i]; pr.Error == nil && isImmediate(pr.Skipped, pr.Action) {
			return deniedPolicy{pr.PolicyName, pr.PolicyVersion, DeniedPhaseResponseBody, true}
		}
	}
	for i := len(headerResults) - 1; i >= 0; i-- {
		if pr := headerResults[i]; isImmediate(pr.Skipped, pr.Action) {
			return deniedPolicy{pr.PolicyName, pr.PolicyVersion, DeniedPhaseResponseHeaders, true}
		}
	}
	return deniedPolicy{}
}

// finishShortCircuitAnalytics completes the analytics payload of any policy
// short-circuit, after the caller has merged what the earlier policies contributed:
//
//  1. The rejecting policy's own metadata goes on top; it wins on any key it sets.
//  2. The engine's attribution is written authoritatively. The terminal reason and,
//     for a policy_denied outcome, the denied-by keys overwrite whatever a policy
//     put there; on any other outcome a policy-supplied denied-by is dropped. They
//     describe what the engine did, so no policy may assert them.
//  3. The caller identity is stamped from SharedContext.AuthContext as one coherent
//     tuple, and only when no policy contributed any identity key — never mixed key by
//     key with another source. The analytics system policy exports identity only in
//     response phases, which never run after a request-phase ImmediateResponse.
//  4. The shared metadata is stamped when no policy contributed it.
func finishShortCircuitAnalytics(
	execCtx *PolicyExecutionContext,
	out map[string]any,
	immResp policy.ImmediateResponse,
	denied deniedPolicy,
) {
	maps.Copy(out, immResp.AnalyticsMetadata)

	// Which of the two policy-layer reasons it is depends on the status: a policy can
	// answer a request as well as refuse it, and a managed Agent Card served with a 200
	// or a conditional-GET 304 is not a denial.
	terminalReason := terminalReasonForImmediateResponse(immResp.StatusCode)
	out[TerminalReasonKey] = terminalReason
	delete(out, DeniedByPolicyKey)
	delete(out, DeniedByPolicyVersionKey)
	delete(out, DeniedPhaseKey)
	if terminalReason == constants.TerminalReasonPolicyDenied && denied.found {
		if denied.name != "" {
			out[DeniedByPolicyKey] = denied.name
		}
		if denied.version != "" {
			out[DeniedByPolicyVersionKey] = denied.version
		}
		out[DeniedPhaseKey] = denied.phase
	}
	attestEngineAttribution(out)

	sc := execCtx.sharedCtx
	if sc == nil {
		return
	}
	if !hasAnyKey(out, authIdentityKeys) {
		maps.Copy(out, authAnalyticsMetadata(sc.AuthContext))
	}
	if _, exists := out[GenericMetadataKey]; !exists {
		if meta := genericMetadataAnalytics(sc.Metadata); meta != "" {
			out[GenericMetadataKey] = meta
		}
	}
}

func hasAnyKey(m map[string]any, keys []string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// collectResponseShortCircuitAnalytics is collectShortCircuitAnalytics for a
// rejection raised by a response-phase policy (e.g. a response guardrail). The
// ImmediateResponse's analytics replace those of every earlier phase on the access log,
// so it is seeded with everything collected so far — the request phases, and the
// response-header phase when a body policy rejected — then the earlier results of this
// pass, then finished like a request-phase short-circuit.
//
// headerResults and bodyResults may each be nil, for a caller where that phase has not
// run in this pass.
func collectResponseShortCircuitAnalytics(
	execCtx *PolicyExecutionContext,
	headerResults []executor.ResponseHeaderPolicyResult,
	bodyResults []executor.ResponsePolicyResult,
	immResp policy.ImmediateResponse,
) map[string]any {
	out := make(map[string]any, len(execCtx.analyticsMetadata)+len(immResp.AnalyticsMetadata))
	maps.Copy(out, execCtx.analyticsMetadata)

	for _, pr := range headerResults {
		if pr.Skipped || pr.Action == nil {
			continue
		}
		if mods, ok := pr.Action.(policy.DownstreamResponseHeaderModifications); ok {
			mergeResponsePolicyAnalytics(execCtx, out, mods.AnalyticsMetadata, mods.AnalyticsHeaderFilter)
		}
	}
	for _, pr := range bodyResults {
		if pr.Skipped || pr.Error != nil || pr.Action == nil {
			continue
		}
		if mods, ok := pr.Action.(policy.DownstreamResponseModifications); ok {
			mergeResponsePolicyAnalytics(execCtx, out, mods.AnalyticsMetadata, mods.AnalyticsHeaderFilter)
		}
	}

	finishShortCircuitAnalytics(execCtx, out, immResp, deniedByResponsePolicy(headerResults, bodyResults))
	return out
}

// mergeResponsePolicyAnalytics folds one response policy result's analytics
// contribution into dest, resolving its header filter against the response headers.
func mergeResponsePolicyAnalytics(
	execCtx *PolicyExecutionContext,
	dest map[string]any,
	metadata map[string]any,
	dropAction policy.DropHeaderAction,
) {
	maps.Copy(dest, metadata)
	if (dropAction.Action != "" || len(dropAction.Headers) > 0) &&
		execCtx.responseBodyCtx != nil && execCtx.responseBodyCtx.ResponseHeaders != nil {
		dest["response_headers"] = finalizeAnalyticsHeaders(dropAction, execCtx.responseBodyCtx.ResponseHeaders.GetAll())
	}
}
