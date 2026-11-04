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
// no response phase runs. Mirrored as dto.PropKeyAuth* / dto.PropKeyMetadata in the
// analytics package; a kernel test asserts the spellings match.
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

// authAnalyticsMetadata mirrors populateAuthAnalyticsMetadata in
// gateway/system-policies/analytics/analytics.go: it walks the auth chain via
// AuthContext.Previous and, for the first layer that is authenticated with a non-empty
// subject, returns the auth-derived analytics keys with the same value encodings —
// audience comma-joined, scopes sorted and space-joined, Properties JSON-encoded,
// Authorized always stamped as "true"/"false". Returns nil when no layer qualifies.
//
// The two must stay identical so the publisher parses one format regardless of
// whether the line came from a completed request or a short-circuit. TokenId is the
// token's identifier (e.g. jti), never the raw token; nothing here is logged.
func authAnalyticsMetadata(authChain *policy.AuthContext) map[string]any {
	for authCtx := authChain; authCtx != nil; authCtx = authCtx.Previous {
		if !authCtx.Authenticated || authCtx.Subject == "" {
			continue
		}
		out := map[string]any{AuthUserIDKey: authCtx.Subject}
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
	return nil
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

// deniedByPolicy identifies the policy whose ImmediateResponse ended the chain: the
// last body-phase result carrying one, else the last header-phase result. Reports
// ok=false when neither phase recorded one (e.g. a caller that only had FinalAction).
func deniedByPolicy(
	headerResults []executor.RequestHeaderPolicyResult,
	bodyResults []executor.RequestPolicyResult,
) (name, version, phase string, ok bool) {
	for i := len(bodyResults) - 1; i >= 0; i-- {
		pr := bodyResults[i]
		if pr.Skipped || pr.Action == nil {
			continue
		}
		if _, isImm := pr.Action.(policy.ImmediateResponse); isImm {
			return pr.PolicyName, pr.PolicyVersion, DeniedPhaseRequestBody, true
		}
	}
	for i := len(headerResults) - 1; i >= 0; i-- {
		pr := headerResults[i]
		if pr.Skipped || pr.Action == nil {
			continue
		}
		if _, isImm := pr.Action.(policy.ImmediateResponse); isImm {
			return pr.PolicyName, pr.PolicyVersion, DeniedPhaseRequestHeaders, true
		}
	}
	return "", "", "", false
}

// setIfAbsent writes value under key only when dest does not already carry it, so a
// value a policy contributed (the rejecting policy's own above all) always wins.
func setIfAbsent(dest map[string]any, key string, value any) {
	if _, exists := dest[key]; !exists {
		dest[key] = value
	}
}

// stampShortCircuitAudit adds the audit facts a short-circuited request would
// otherwise lose: which policy denied it, and the caller identity and shared metadata
// that the analytics system policy only exports in response phases (which never run
// after an ImmediateResponse). Every key is set only when absent.
func stampShortCircuitAudit(
	execCtx *PolicyExecutionContext,
	out map[string]any,
	headerResults []executor.RequestHeaderPolicyResult,
	bodyResults []executor.RequestPolicyResult,
	terminalReason string,
) {
	if terminalReason == constants.TerminalReasonPolicyDenied {
		if name, version, phase, ok := deniedByPolicy(headerResults, bodyResults); ok {
			if name != "" {
				setIfAbsent(out, DeniedByPolicyKey, name)
			}
			if version != "" {
				setIfAbsent(out, DeniedByPolicyVersionKey, version)
			}
			setIfAbsent(out, DeniedPhaseKey, phase)
		}
	}

	sc := execCtx.sharedCtx
	if sc == nil {
		return
	}
	for k, v := range authAnalyticsMetadata(sc.AuthContext) {
		setIfAbsent(out, k, v)
	}
	if meta := genericMetadataAnalytics(sc.Metadata); meta != "" {
		setIfAbsent(out, GenericMetadataKey, meta)
	}
}
