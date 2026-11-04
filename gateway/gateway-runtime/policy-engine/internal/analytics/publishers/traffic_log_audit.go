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

// actClaim is the RFC 8693 actor claim. AuthContext.Properties flattens every claim to
// a string, so a delegation chain arrives as a JSON-encoded string; it is decoded back
// into nested objects so act.sub / act.act.sub stay addressable in the log.
const actClaim = "act"

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
	// Authenticated is derived exactly as the global properties' auth.authenticated:
	// true when a subject is present. Never false-valued — omitted otherwise.
	Authenticated *bool    `json:"authenticated,omitempty"`
	Type          string   `json:"type,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	ClientID      string   `json:"clientId,omitempty"`
	TokenID       string   `json:"tokenId,omitempty"`
	Audience      []string `json:"audience,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	Authorized    *bool    `json:"authorized,omitempty"`
	// Claims are AuthContext.Properties — custom claims only; the raw token is
	// never part of them.
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

// buildAuthBlock maps the auth-context properties onto TrafficLogAuth. Nil when none
// is present.
func buildAuthBlock(props map[string]interface{}) *TrafficLogAuth {
	a := &TrafficLogAuth{
		Subject:  propString(props, dto.PropKeyAuthUserID),
		Type:     propString(props, dto.PropKeyAuthType),
		Issuer:   propString(props, dto.PropKeyAuthIssuer),
		ClientID: propString(props, dto.PropKeyAuthCredentialID),
		TokenID:  propString(props, dto.PropKeyAuthTokenID),
		Audience: splitAuthAudience(propString(props, dto.PropKeyAuthAudience)),
		Scopes:   splitAuthScopes(propString(props, dto.PropKeyAuthScopes)),
		Claims:   decodeAuthClaims(propString(props, dto.PropKeyAuthProperties)),
	}
	if a.Subject != "" {
		authenticated := true
		a.Authenticated = &authenticated
	}
	if raw := propString(props, dto.PropKeyAuthAuthorized); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			a.Authorized = &parsed
		}
	}
	if a.Subject == "" && a.Type == "" && a.Issuer == "" && a.ClientID == "" && a.TokenID == "" &&
		len(a.Audience) == 0 && len(a.Scopes) == 0 && len(a.Claims) == 0 && a.Authorized == nil {
		return nil
	}
	return a
}

// decodeAuthClaims decodes the JSON-encoded AuthContext.Properties. The collector
// marshals a map[string]string, so every value is a string; the act claim is decoded
// once more when its string is itself a JSON object, restoring the delegation chain as
// nested objects. A value that already arrives as an object is kept as-is.
func decodeAuthClaims(raw string) map[string]any {
	if raw == "" {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		slog.Debug("traffic log: failed to parse auth properties metadata", "error", err)
		return nil
	}
	if s, ok := claims[actClaim].(string); ok && strings.HasPrefix(strings.TrimSpace(s), "{") {
		var act map[string]any
		if err := json.Unmarshal([]byte(s), &act); err == nil {
			claims[actClaim] = act
		}
	}
	if len(claims) == 0 {
		return nil
	}
	return claims
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

// buildDecisionBlock maps the kernel's terminal-reason and denied-by stamps.
func buildDecisionBlock(props map[string]interface{}) *TrafficLogDecision {
	d := &TrafficLogDecision{TerminalReason: propString(props, dto.PropKeyTerminalReason)}
	deniedBy := TrafficLogDeniedBy{
		Policy:  propString(props, dto.PropKeyDeniedByPolicy),
		Version: propString(props, dto.PropKeyDeniedByPolicyVersion),
		Phase:   propString(props, dto.PropKeyDeniedPhase),
	}
	if deniedBy != (TrafficLogDeniedBy{}) {
		d.DeniedBy = &deniedBy
	}
	if d.TerminalReason == "" && d.DeniedBy == nil {
		return nil
	}
	return d
}
