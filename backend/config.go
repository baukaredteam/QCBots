package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Config holds all application configuration loaded from YAML files and env vars.
type Config struct {
	Clients       []ClientConfig       `yaml:"clients"`
	Sectors       []SectorConfig       `yaml:"sectors"`
	Harnesses     []HarnessConfig      `yaml:"harnesses"`
	ModelProviders []ModelProviderConfig `yaml:"providers"`
	DBPath        string
	ServerPort    string
	ListenAddr    string
	Origin        string
}

type ClientConfig struct {
	ClientID   string `yaml:"client_id"`
	ClientName string `yaml:"client_name"`
	Sector     string `yaml:"sector"`
	Status     string `yaml:"status"`
}

type SectorConfig struct {
	SectorID   string `yaml:"sector_id"`
	SectorName string `yaml:"sector_name"`
	Description string `yaml:"description"`
}

type HarnessConfig struct {
	AgentID   string   `yaml:"agent_id"`
	AgentName string   `yaml:"agent_name"`
	Status    string   `yaml:"status"`
	Endpoint  string   `yaml:"endpoint,omitempty"`
	HarnessType string `yaml:"harness_type,omitempty"`
	IntegrationType string `yaml:"integration_type,omitempty"`
	Version   string   `yaml:"version,omitempty"`
	Capabilities []string `yaml:"capabilities,omitempty"`
	AllowedClients []string `yaml:"allowed_clients,omitempty"`
	AllowedTools []string `yaml:"allowed_tools,omitempty"`
	PermissionProfile string `yaml:"permission_profile,omitempty"`
	TrustLevel string `yaml:"trust_level,omitempty"`
}

type ModelProviderConfig struct {
	ProviderID   string `yaml:"provider_id"`
	ProviderName string `yaml:"provider_name"`
	Status       string `yaml:"status"`
}

// LoadConfig reads YAML config files from the config directory and applies env var overrides.
func LoadConfig(configDir string) (*Config, error) {
	cfg := &Config{
		DBPath:    getEnv("WORKBENCH_DB_PATH", filepath.Join("..", "storage", "workbench.db")),
		ServerPort: getEnv("WORKBENCH_PORT", "8080"),
		ListenAddr: getEnv("WORKBENCH_LISTEN_ADDR", "127.0.0.1"),
		Origin:    getEnv("WORKBENCH_ORIGIN", "http://localhost:5173"),
	}

	// Load clients.yaml
	clients, err := loadClients(filepath.Join(configDir, "clients.yaml"))
	if err != nil {
		return nil, fmt.Errorf("loading clients: %w", err)
	}
	cfg.Clients = clients

	// Load sectors.yaml
	sectors, err := loadSectors(filepath.Join(configDir, "sectors.yaml"))
	if err != nil {
		return nil, fmt.Errorf("loading sectors: %w", err)
	}
	cfg.Sectors = sectors

	// Load harness_registry.yaml
	harnesses, err := loadHarnesses(filepath.Join(configDir, "harness_registry.yaml"))
	if err != nil {
		return nil, fmt.Errorf("loading harnesses: %w", err)
	}
	cfg.Harnesses = harnesses

	// Load model_providers.yaml
	providers, err := loadProviders(filepath.Join(configDir, "model_providers.yaml"))
	if err != nil {
		return nil, fmt.Errorf("loading model providers: %w", err)
	}
	cfg.ModelProviders = providers

	return cfg, nil
}

func loadClients(path string) ([]ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Clients []ClientConfig `yaml:"clients"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Clients, nil
}

func loadSectors(path string) ([]SectorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Sectors []SectorConfig `yaml:"sectors"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Sectors, nil
}

func loadHarnesses(path string) ([]HarnessConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Harnesses []HarnessConfig `yaml:"harnesses"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Harnesses, nil
}

func loadProviders(path string) ([]ModelProviderConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Providers []ModelProviderConfig `yaml:"providers"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Providers, nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// ClientAccess maps a user_id to the set of client_ids they are authorized to access.
type ClientAccess struct {
	UserID      string
	ClientIDs   map[string]bool
}

// IsAuthorized checks if the user has access to the given client.
func (ca *ClientAccess) IsAuthorized(userID, clientID string) bool {
	if ca.UserID != userID {
		return false
	}
	return ca.ClientIDs[clientID]
}

// ClientAccessStore maps database user_id to their authorized client set.
var ClientAccessStore = map[string]*ClientAccess{
	"user-analyst-alpha": {
		UserID:    "user-analyst-alpha",
		ClientIDs: map[string]bool{"client-alpha": true},
	},
	"user-analyst-beta": {
		UserID:    "user-analyst-beta",
		ClientIDs: map[string]bool{"client-beta": true},
	},
	"user-analyst-multi": {
		UserID:    "user-analyst-multi",
		ClientIDs: map[string]bool{"client-alpha": true, "client-beta": true},
	},
	"user-admin": {
		UserID:    "user-admin",
		ClientIDs: map[string]bool{"client-alpha": true, "client-beta": true},
	},
}

// IsClientAccessible checks if a user can access a given client.
//
// Single source of truth: persistent user_authorized_clients table.
// Fail-closed: any database error or missing grant results in false.
//
// ClientAccessStore is retained for backward compatibility but is not
// consulted by this function.
func IsClientAccessible(userID, clientID string) bool {
	if globalDB == nil {
		return false
	}
	return globalDB.CanAccessClient(userID, clientID)
}

// String implements fmt.Stringer for Config.
func (c *Config) String() string {
	var sb strings.Builder
	sb.WriteString("Config{\n")
	sb.WriteString(fmt.Sprintf("  DBPath: %s\n", c.DBPath))
	sb.WriteString(fmt.Sprintf("  ServerPort: %s\n", c.ServerPort))
	sb.WriteString(fmt.Sprintf("  Clients: %d\n", len(c.Clients)))
	sb.WriteString(fmt.Sprintf("  Sectors: %d\n", len(c.Sectors)))
	sb.WriteString(fmt.Sprintf("  Harnesses: %d\n", len(c.Harnesses)))
	sb.WriteString(fmt.Sprintf("  ModelProviders: %d\n", len(c.ModelProviders)))
	sb.WriteString("}")
	return sb.String()
}
