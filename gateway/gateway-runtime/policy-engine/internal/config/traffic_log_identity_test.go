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

package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const trafficLogIdentityBase = `
[policy_engine.config_mode]
mode = "file"

[policy_engine.file_config]
path = "configs/policy-chains.yaml"
`

func TestTrafficLoggingGatewayIdentity(t *testing.T) {
	t.Run("defaults are empty", func(t *testing.T) {
		tl := defaultConfig().TrafficLogging
		assert.Empty(t, tl.GatewayID)
		assert.Empty(t, tl.Organization)
		assert.Empty(t, tl.Environment)
	})

	t.Run("unset in TOML stays empty", func(t *testing.T) {
		cfg, err := Load(writePEInterpConfig(t, trafficLogIdentityBase))
		require.NoError(t, err)
		assert.Empty(t, cfg.TrafficLogging.GatewayID)
		assert.Empty(t, cfg.TrafficLogging.Organization)
		assert.Empty(t, cfg.TrafficLogging.Environment)
	})

	t.Run("literal TOML values load", func(t *testing.T) {
		cfg, err := Load(writePEInterpConfig(t, trafficLogIdentityBase+`
[traffic_logging]
gateway_id = "gw-1"
organization = "org-a"
environment = "dev"
`))
		require.NoError(t, err)
		assert.Equal(t, "gw-1", cfg.TrafficLogging.GatewayID)
		assert.Equal(t, "org-a", cfg.TrafficLogging.Organization)
		assert.Equal(t, "dev", cfg.TrafficLogging.Environment)
	})

	t.Run("env interpolation loads", func(t *testing.T) {
		t.Setenv("TL_GATEWAY_ID", "gw-from-env")
		t.Setenv("TL_ORG", "org-from-env")
		cfg, err := Load(writePEInterpConfig(t, trafficLogIdentityBase+`
[traffic_logging]
gateway_id = '{{ env "TL_GATEWAY_ID" }}'
organization = '{{ env "TL_ORG" }}'
environment = '{{ env "TL_ENV_UNSET" "fallback-env" }}'
`))
		require.NoError(t, err)
		assert.Equal(t, "gw-from-env", cfg.TrafficLogging.GatewayID)
		assert.Equal(t, "org-from-env", cfg.TrafficLogging.Organization)
		assert.Equal(t, "fallback-env", cfg.TrafficLogging.Environment)
	})

	t.Run("shipped template matches the defaults", func(t *testing.T) {
		cfg, err := Load(filepath.Join("..", "..", "..", "..", "configs", "config-template.toml"))
		require.NoError(t, err)
		assert.Empty(t, cfg.TrafficLogging.GatewayID)
		assert.Empty(t, cfg.TrafficLogging.Organization)
		assert.Empty(t, cfg.TrafficLogging.Environment)
	})
}

func TestTrafficLoggingAuditClaims(t *testing.T) {
	t.Run("default is act only", func(t *testing.T) {
		assert.Equal(t, []string{"act"}, defaultConfig().TrafficLogging.AuditClaims)
		cfg, err := Load(writePEInterpConfig(t, trafficLogIdentityBase))
		require.NoError(t, err)
		assert.Equal(t, []string{"act"}, cfg.TrafficLogging.AuditClaims)
	})

	t.Run("empty list emits none", func(t *testing.T) {
		cfg, err := Load(writePEInterpConfig(t, trafficLogIdentityBase+`
[traffic_logging]
audit_claims = []
`))
		require.NoError(t, err)
		assert.Empty(t, cfg.TrafficLogging.AuditClaims, "an explicit [] must replace the default, not keep act")
	})

	t.Run("custom list", func(t *testing.T) {
		cfg, err := Load(writePEInterpConfig(t, trafficLogIdentityBase+`
[traffic_logging]
audit_claims = ["act", "client_id"]
`))
		require.NoError(t, err)
		assert.Equal(t, []string{"act", "client_id"}, cfg.TrafficLogging.AuditClaims)
	})

	t.Run("shipped template matches the default", func(t *testing.T) {
		cfg, err := Load(filepath.Join("..", "..", "..", "..", "configs", "config-template.toml"))
		require.NoError(t, err)
		assert.Equal(t, []string{"act"}, cfg.TrafficLogging.AuditClaims)
	})
}

func TestTrafficLoggingTokenFingerprintKey(t *testing.T) {
	t.Run("default empty", func(t *testing.T) {
		assert.Equal(t, "", defaultConfig().TrafficLogging.TokenFingerprintKey)
	})
	t.Run("loads a long enough key", func(t *testing.T) {
		cfg, err := Load(writePEInterpConfig(t, trafficLogIdentityBase+`
[traffic_logging]
token_fingerprint_key = "0123456789abcdef0123456789abcdef"
`))
		require.NoError(t, err)
		assert.Equal(t, "0123456789abcdef0123456789abcdef", cfg.TrafficLogging.TokenFingerprintKey)
	})
	t.Run("rejects a short key", func(t *testing.T) {
		_, err := Load(writePEInterpConfig(t, trafficLogIdentityBase+`
[traffic_logging]
token_fingerprint_key = "too-short"
`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token_fingerprint_key")
	})
}
