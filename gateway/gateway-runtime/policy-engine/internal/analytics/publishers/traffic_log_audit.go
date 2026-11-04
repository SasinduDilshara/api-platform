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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"

	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/analytics/dto"
	"github.com/wso2/api-platform/gateway/gateway-runtime/policy-engine/internal/constants"
)

// Event properties the collector assembles the AI and MCP facts under. In-process
// handles, spelled here because publishers do not import the analytics package.
const (
	aiMetadataProperty   = "aiMetadata"
	aiTokenUsageProperty = "aiTokenUsage"
	mcpAnalyticsProperty = "mcpAnalytics"
)

// TrafficLogGateway identifies the emitting gateway, from [traffic_logging] config.
type TrafficLogGateway struct {
	ID           string `json:"id,omitempty"`
	Organization string `json:"organization,omitempty"`
	Environment  string `json:"environment,omitempty"`
}

// TrafficLogAuth is the caller identity, from the auth-context properties the
// collector system policy (or, on a policy short-circuit, the kernel) stamps.
type TrafficLogAuth struct {
	Subject string `json:"subject,omitempty"`
	// Authenticated is derived exactly as the global properties' auth.authenticated
	// (see authContextAuthenticated). Never false-valued — omitted otherwise.
	Authenticated *bool    `json:"authenticated,omitempty"`
	Type          string   `json:"type,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	ClientID      string   `json:"clientId,omitempty"`
	TokenID       string   `json:"tokenId,omitempty"`
	Audience      []string `json:"audience,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	Authorized    *bool    `json:"authorized,omitempty"`
	// Claims are the AuthContext.Properties named in traffic_logging.audit_claims —
	// custom claims only; the raw token is never part of them.
	Claims map[string]any `json:"claims,omitempty"`
}

// TrafficLogAI carries the LLM facts of the request.
type TrafficLogAI struct {
	Provider string `json:"provider,omitempty"`
	// ProviderVersion is dto.AIMetadata.VendorVersion, which the collector fills from
	// the API version (x-wso2-api-version) of the provider API.
	ProviderVersion string `json:"providerVersion,omitempty"`
	Model           string `json:"model,omitempty"`
	RequestModel    string `json:"requestModel,omitempty"`
	// Token counts are omitted when zero: the collector cannot tell a missing count
	// from a zero one.
	PromptTokens     int `json:"promptTokens,omitempty"`
	CompletionTokens int `json:"completionTokens,omitempty"`
	TotalTokens      int `json:"totalTokens,omitempty"`
	// Cost is a float64 when the llm-cost value parsed as a number, else the raw string.
	Cost any `json:"cost,omitempty"`
}

// TrafficLogMCPClientInfo is the client's self-description from an MCP request.
type TrafficLogMCPClientInfo struct {
	RequestedProtocolVersion string `json:"requestedProtocolVersion,omitempty"`
	Name                     string `json:"name,omitempty"`
	Version                  string `json:"version,omitempty"`
}

// TrafficLogMCP carries the MCP JSON-RPC facts of the request.
type TrafficLogMCP struct {
	Method      string                   `json:"method,omitempty"`
	ID          string                   `json:"id,omitempty"`
	Capability  string                   `json:"capability,omitempty"`
	Name        string                   `json:"name,omitempty"`
	ResourceURI string                   `json:"resourceUri,omitempty"`
	SessionID   string                   `json:"sessionId,omitempty"`
	ClientInfo  *TrafficLogMCPClientInfo `json:"clientInfo,omitempty"`
	IsError     *bool                    `json:"isError,omitempty"`
	// ErrorCode is a JSON-RPC error code as a number, or the raw string a policy
	// supplied when it was not an integer.
	ErrorCode  any    `json:"errorCode,omitempty"`
	ResultType string `json:"resultType,omitempty"`
	ServerInfo any    `json:"serverInfo,omitempty"`
}

// TrafficLogGuardrail records a guardrail intervention.
type TrafficLogGuardrail struct {
	Hit  bool   `json:"hit"`
	Name string `json:"name,omitempty"`
}

// TrafficLogDeniedBy names the policy that denied the request.
type TrafficLogDeniedBy struct {
	Policy  string `json:"policy,omitempty"`
	Version string `json:"version,omitempty"`
	Phase   string `json:"phase,omitempty"`
}

// TrafficLogDecision is the engine's own attribution of a request it ended.
type TrafficLogDecision struct {
	TerminalReason string              `json:"terminalReason,omitempty"`
	DeniedBy       *TrafficLogDeniedBy `json:"deniedBy,omitempty"`
}

// newTrafficLogGateway returns nil when no identity is configured, so the block is
// omitted entirely.
func newTrafficLogGateway(id, organization, environment string) *TrafficLogGateway {
	gw := TrafficLogGateway{ID: id, Organization: organization, Environment: environment}
	if gw == (TrafficLogGateway{}) {
		return nil
	}
	return &gw
}

// propString returns the string property at key, or "".
func propString(props map[string]interface{}, key string) string {
	s, _ := props[key].(string)
	return s
}

// splitAuthAudience and splitAuthScopes undo the collector's encodings (audience
// comma-joined, scopes space-joined). Shared with the global properties' auth.*
// variables so both read one format.
func splitAuthAudience(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func splitAuthScopes(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, " ")
}

// authContextAuthenticated reports whether the event carries an authenticated
// identity. The collector (and the kernel, on a denial) stamps the auth-context keys
// only for an authenticated layer, and always stamps x-wso2-auth-authorized with them;
// a layer without a subject — api-key-auth sets none — is still authenticated. Shared
// with the global properties' auth.authenticated so both agree.
func authContextAuthenticated(props map[string]interface{}) bool {
	return propString(props, dto.PropKeyAuthUserID) != "" || propString(props, dto.PropKeyAuthAuthorized) != ""
}

// buildAuthBlock maps the auth-context properties onto TrafficLogAuth, emitting only
// the claims named in allowedClaims. Nil when none is present.
// protectTokenID keeps credential fingerprints out of the log. A token id that is a
// SHA-256 hex digest is the unsalted hash of a raw credential (api-key-auth, opaque
// tokens) — the value a key store keeps as its verifier — so it is replaced by
// "hmac-sha256:" + hex(HMAC-SHA256(key, id)), or dropped when no key is configured.
// Any other id (a JWT jti) is a token identifier, not a credential, and passes through.
func protectTokenID(id string, key []byte) string {
	if !isSHA256Hex(id) {
		return id
	}
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.ToLower(id)))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// isSHA256Hex reports whether s is exactly 64 hexadecimal characters.
func isSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func buildAuthBlock(props map[string]interface{}, allowedClaims map[string]bool) *TrafficLogAuth {
	a := &TrafficLogAuth{
		Subject:  propString(props, dto.PropKeyAuthUserID),
		Type:     propString(props, dto.PropKeyAuthType),
		Issuer:   propString(props, dto.PropKeyAuthIssuer),
		ClientID: propString(props, dto.PropKeyAuthCredentialID),
		TokenID:  propString(props, dto.PropKeyAuthTokenID),
		Audience: splitAuthAudience(propString(props, dto.PropKeyAuthAudience)),
		Scopes:   splitAuthScopes(propString(props, dto.PropKeyAuthScopes)),
		Claims:   decodeAuthClaims(propString(props, dto.PropKeyAuthProperties), allowedClaims),
	}
	if authContextAuthenticated(props) {
		authenticated := true
		a.Authenticated = &authenticated
	}
	if raw := propString(props, dto.PropKeyAuthAuthorized); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			a.Authorized = &parsed
		}
	}
	if a.Subject == "" && a.Type == "" && a.Issuer == "" && a.ClientID == "" && a.TokenID == "" &&
		len(a.Audience) == 0 && len(a.Scopes) == 0 && len(a.Claims) == 0 && a.Authorized == nil &&
		a.Authenticated == nil {
		return nil
	}
	return a
}

// decodeAuthClaims decodes the JSON-encoded AuthContext.Properties and keeps only the
// claims named in allowed (claims are personal data; nothing is emitted unless the
// operator listed it). The collector marshals a map[string]string, so every value is a
// string, and auth policies flatten a structured claim (an object or array, e.g. the
// RFC 8693 act chain or groups) into a JSON string; such a value is decoded back so it
// stays addressable (act.sub, act.act.sub). A value that already arrives decoded is
// kept as-is. Malformed input yields no claims.
func decodeAuthClaims(raw string, allowed map[string]bool) map[string]any {
	if raw == "" || len(allowed) == 0 {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		slog.Debug("traffic log: failed to parse auth properties metadata", "error", err)
		return nil
	}
	out := make(map[string]any, len(allowed))
	for name, value := range claims {
		if !allowed[name] {
			continue
		}
		if str, ok := value.(string); ok {
			if trimmed := strings.TrimSpace(str); strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
				var decoded any
				if err := json.Unmarshal([]byte(trimmed), &decoded); err == nil {
					value = decoded
				}
			}
		}
		out[name] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildAIBlock maps the collector's aiMetadata/aiTokenUsage/requestModel properties.
// Emitted only when aiMetadata is present; the token-usage hour is not carried.
func buildAIBlock(props map[string]interface{}) *TrafficLogAI {
	var meta *dto.AIMetadata
	switch v := props[aiMetadataProperty].(type) {
	case dto.AIMetadata:
		meta = &v
	case *dto.AIMetadata:
		meta = v
	}
	if meta == nil {
		return nil
	}
	ai := &TrafficLogAI{
		Provider:        meta.VendorName,
		ProviderVersion: meta.VendorVersion,
		Model:           meta.Model,
		RequestModel:    propString(props, constants.RequestModelPropertyKey),
		Cost:            meta.LLMCost,
	}
	var usage *dto.AITokenUsage
	switch v := props[aiTokenUsageProperty].(type) {
	case dto.AITokenUsage:
		usage = &v
	case *dto.AITokenUsage:
		usage = v
	}
	if usage != nil {
		ai.PromptTokens = usage.PromptToken
		ai.CompletionTokens = usage.CompletionToken
		ai.TotalTokens = usage.TotalToken
	}
	return ai
}

// buildMCPBlock maps the flattened mcpAnalytics map (McpRequestAnalyticsProperties and
// McpResponseAnalyticsProperties merged, plus sessionId). Nil when nothing is present.
func buildMCPBlock(props map[string]interface{}) *TrafficLogMCP {
	m, ok := props[mcpAnalyticsProperty].(map[string]interface{})
	if !ok || len(m) == 0 {
		return nil
	}
	// The collector falls back to the raw strings when a policy's MCP properties did
	// not parse; they have no fixed shape, so they are not mapped into the block.
	if _, raw := m["mcp_request_properties"]; raw {
		slog.Debug("traffic log: unparsed MCP request properties not mapped to the mcp block")
	}
	if _, raw := m["mcp_response_properties"]; raw {
		slog.Debug("traffic log: unparsed MCP response properties not mapped to the mcp block")
	}
	str := func(key string) string { s, _ := m[key].(string); return s }
	mcp := &TrafficLogMCP{
		Method:      str("jsonRpcMethod"),
		ID:          str("jsonRpcId"),
		Capability:  str("capability"),
		Name:        str("capabilityName"),
		ResourceURI: str("resourceUri"),
		SessionID:   str("sessionId"),
		ResultType:  str("resultType"),
		ErrorCode:   m["errorCode"],
		ServerInfo:  m["serverInfo"],
	}
	if b, ok := m["isError"].(bool); ok {
		mcp.IsError = &b
	}
	if ci, ok := m["clientInfo"].(map[string]interface{}); ok {
		info := TrafficLogMCPClientInfo{}
		info.RequestedProtocolVersion, _ = ci["requestedProtocolVersion"].(string)
		info.Name, _ = ci["name"].(string)
		info.Version, _ = ci["version"].(string)
		if info != (TrafficLogMCPClientInfo{}) {
			mcp.ClientInfo = &info
		}
	}
	if mcp.Method == "" && mcp.ID == "" && mcp.Capability == "" && mcp.Name == "" && mcp.ResourceURI == "" &&
		mcp.SessionID == "" && mcp.ResultType == "" && mcp.ErrorCode == nil && mcp.ServerInfo == nil &&
		mcp.IsError == nil && mcp.ClientInfo == nil {
		return nil
	}
	return mcp
}

// buildA2ABlock returns the collector's typed A2A dimensions as-is.
func buildA2ABlock(props map[string]interface{}) *dto.A2AAnalytics {
	a2a, _ := props[a2aAnalyticsProperty].(*dto.A2AAnalytics)
	return a2a
}

// buildGuardrailBlock is emitted only when a guardrail was hit or named.
func buildGuardrailBlock(props map[string]interface{}) *TrafficLogGuardrail {
	hit, _ := props[constants.GuardrailHitMetadataKey].(bool)
	name := propString(props, constants.GuardrailNameMetadataKey)
	if !hit && name == "" {
		return nil
	}
	return &TrafficLogGuardrail{Hit: hit, Name: name}
}

// buildDecisionBlock maps the kernel's terminal-reason and denied-by stamps. deniedBy
// is emitted only for a policy_denied outcome: the kernel writes it only then, and a
// stray value on any other line is not an engine fact.
func buildDecisionBlock(props map[string]interface{}) *TrafficLogDecision {
	d := &TrafficLogDecision{TerminalReason: propString(props, dto.PropKeyTerminalReason)}
	if d.TerminalReason != constants.TerminalReasonPolicyDenied {
		if d.TerminalReason == "" {
			return nil
		}
		return d
	}
	deniedBy := TrafficLogDeniedBy{
		Policy:  propString(props, dto.PropKeyDeniedByPolicy),
		Version: propString(props, dto.PropKeyDeniedByPolicyVersion),
		Phase:   propString(props, dto.PropKeyDeniedPhase),
	}
	if deniedBy != (TrafficLogDeniedBy{}) {
		d.DeniedBy = &deniedBy
	}
	return d
}
