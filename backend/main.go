package main

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var globalDB *DB
var globalConfig *Config
var globalAuditLogger *AuditLogger
var globalCSRFValidator *CSRFValidator
var isSecure = false

var tenantMW *TenantMiddleware

// rateLimiter implements a simple per-IP rate limiter for login attempts.
type rateLimiter struct {
	mu      sync.Mutex
	clients map[string][]time.Time // IP -> list of attempt timestamps
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{clients: make(map[string][]time.Time)}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Minute) // 1-minute window

	// Filter out old attempts
	var recent []time.Time
	for _, t := range rl.clients[ip] {
		if t.After(windowStart) {
			recent = append(recent, t)
		}
	}

	// Max 5 login attempts per minute per IP
	if len(recent) >= 5 {
		rl.clients[ip] = recent
		return false
	}

	recent = append(recent, now)
	rl.clients[ip] = recent
	return true
}

var globalRateLimiter = newRateLimiter()

type contextKey int

const (
	sessionCtxKey contextKey = iota
)

func init() {
	tenantMW = &TenantMiddleware{}
}

func main() {
	var err error

	// M7-E: forward migrations-only and backup commands before config parsing.
	//   workbench migrate <db>
	//   workbench backup-sqlite <source-db> <new-backup-file>
	if len(os.Args) > 2 && os.Args[1] == "migrate" {
		if err := runMigrateCommand(os.Args[2]); err != nil {
			log.Fatalf("migrate: %v", err)
		}
		return
	}
	if len(os.Args) > 3 && os.Args[1] == "backup-sqlite" {
		if err := backupSQLite(os.Args[2], os.Args[3]); err != nil {
			log.Fatalf("backup-sqlite: %v", err)
		}
		fmt.Printf("backup verified: %s\n", os.Args[3])
		return
	}

	// Test seeders create synthetic users and tenants. They are refused unless
	// the operator explicitly enables them for a disposable environment.
	if len(os.Args) > 2 && os.Args[1] == "seed-stagef" {
		if err := requireTestSeederEnv(); err != nil {
			log.Fatalf("seed-stagef: %v", err)
		}
		if err := seedStageFDB(os.Args[2]); err != nil {
			log.Fatalf("seed-stagef: %v", err)
		}
		return
	}

	// M7-D 2B-4B isolated acceptance DB: go run . seed-hunt-acceptance /path/to.db
	// Synthetic fixtures only. Refuses workbench.db, never contacts QRadar.
	if len(os.Args) > 2 && os.Args[1] == "seed-hunt-acceptance" {
		if err := requireTestSeederEnv(); err != nil {
			log.Fatalf("seed-hunt-acceptance: %v", err)
		}
		if err := seedHuntAcceptance(os.Args[2]); err != nil {
			log.Fatalf("seed-hunt-acceptance: %v", err)
		}
		return
	}

	configDir := filepath.Join("..", "config")
	if len(os.Args) > 1 {
		if os.Args[1] == "mcp-stdio" && len(os.Args) > 2 {
			configDir = os.Args[2]
		} else {
			configDir = os.Args[1]
		}
	}

	globalConfig, err = LoadConfig(configDir)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Configuration loaded: %d clients, %d sectors", len(globalConfig.Clients), len(globalConfig.Sectors))

	globalDB, err = OpenDB(globalConfig.DBPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer globalDB.Close()
	log.Printf("Database opened: %s", globalConfig.DBPath)

	isSecure = globalConfig.ServerPort == "443" || os.Getenv("WORKBENCH_SECURE") == "true"

	trustedProxies, trustedHops, err := loadTrustedProxyConfig()
	if err != nil {
		log.Fatalf("invalid trusted proxy configuration: %v", err)
	}
	if trustedProxies.enabled() {
		log.Printf("Trusted proxy networks configured: %d, trusted hops: %d", len(trustedProxies.nets), trustedHops)
	} else {
		log.Printf("No trusted proxies configured: forwarded headers will be rejected")
	}

	// Fail fast on an unmigrated database instead of serving 503s from every
	// feature endpoint. Applied to HTTP mode only: MCP stdio has its own schema
	// expectations and is not a pilot HTTP surface.
	globalAuditLogger = NewAuditLogger(globalDB)
	allowedOrigins := []string{globalConfig.Origin}
	globalCSRFValidator = NewCSRFValidator(allowedOrigins, isSecure)

	// Seed harness registry from config and register adapters
	if err := seedHarnessesFromConfig(globalDB, globalConfig.Harnesses); err != nil {
		log.Printf("Warning: seeding harnesses: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", handleHealth)
	mux.HandleFunc("GET /api/v1/test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"test works"}`))
	})

	mux.HandleFunc("POST /api/v1/auth/login", handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", applyMiddleware(http.HandlerFunc(handleLogout), requireAuth, auditWrap, csrfWrap))
	mux.HandleFunc("GET /api/v1/auth/me", applyMiddleware(http.HandlerFunc(handleMe), requireAuth, auditWrap))

	mux.HandleFunc("GET /api/v1/tenants/{client_id}/cti/reports",
		applyMiddleware(http.HandlerFunc(handleTenantCTIReports),
			requireAuth,
			requirePermission(CanViewCTI),
			tenantMW.RequireTenantAccess,
			auditWrap,
			csrfWrap))

	// CTI import & analysis API
	mux.HandleFunc("POST /api/v1/cti/import",
		applyMiddleware(http.HandlerFunc(handleCTIImport),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}",
		applyMiddleware(http.HandlerFunc(handleCTIReportDetail),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/analyze",
		applyMiddleware(http.HandlerFunc(handleCTIAnalyze),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/iocs",
		applyMiddleware(http.HandlerFunc(handleCTIIOCs),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/ttps",
		applyMiddleware(http.HandlerFunc(handleCTITTPs),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/cves",
		applyMiddleware(http.HandlerFunc(handleCTICVEs),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/evidence",
		applyMiddleware(http.HandlerFunc(handleCTIEvidence),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/provenance",
		applyMiddleware(http.HandlerFunc(handleCTIProvenance),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	// Case list/create endpoints (M6 Stage B).
	mux.HandleFunc("GET /api/v1/cases",
		applyMiddleware(http.HandlerFunc(handleListCases),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/cases",
		applyMiddleware(http.HandlerFunc(handleCreateCase),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("PUT /api/v1/cases/{case_id}/status",
		applyMiddleware(http.HandlerFunc(handleTransitionCaseStatus),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/cases/{case_id}/participants",
		applyMiddleware(http.HandlerFunc(handleAddCaseParticipant),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/cases/{case_id}/participants",
		applyMiddleware(http.HandlerFunc(handleListCaseParticipants),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("DELETE /api/v1/cases/{case_id}/participants/{user_id}",
		applyMiddleware(http.HandlerFunc(handleRemoveCaseParticipant),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))

	// M6 Stage D: artifacts review, notes, activity.
	mux.HandleFunc("PUT /api/v1/cases/{case_id}/artifacts/{artifact_id}/review",
		applyMiddleware(http.HandlerFunc(handleReviewArtifact),
			requireAuth,
			requirePermission(CanReviewArtifact),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/cases/{case_id}/notes",
		applyMiddleware(http.HandlerFunc(handleCreateNote),
			requireAuth,
			requirePermission(CanCreateNote),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/cases/{case_id}/notes",
		applyMiddleware(http.HandlerFunc(handleListNotes),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("GET /api/v1/cases/{case_id}/activity",
		applyMiddleware(http.HandlerFunc(handleListActivity),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	// M6 Stage E: hypothesis & investigation linking.
	mux.HandleFunc("POST /api/v1/cases/{case_id}/hypotheses/{hypothesis_id}",
		applyMiddleware(http.HandlerFunc(handleLinkHypothesis),
			requireAuth,
			requirePermission(CanLinkHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("DELETE /api/v1/cases/{case_id}/hypotheses/{hypothesis_id}",
		applyMiddleware(http.HandlerFunc(handleUnlinkHypothesis),
			requireAuth,
			requirePermission(CanLinkHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/cases/{case_id}/hypotheses",
		applyMiddleware(http.HandlerFunc(handleListHypotheses),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/cases/{case_id}/hypotheses/{hypothesis_id}/review",
		applyMiddleware(http.HandlerFunc(handleReviewHypothesis),
			requireAuth,
			requirePermission(CanReviewHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/cases/{case_id}/investigations",
		applyMiddleware(http.HandlerFunc(handleCreateInvestigation),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/cases/{case_id}/investigations",
		applyMiddleware(http.HandlerFunc(handleListInvestigations),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	// M7-B: CTI Report <-> Case links.
	mux.HandleFunc("GET /api/v1/cases/{case_id}/cti-reports",
		applyMiddleware(http.HandlerFunc(handleListCaseCTIReports),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/cases/{case_id}/cti-reports",
		applyMiddleware(http.HandlerFunc(handleLinkCaseCTIReport),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("DELETE /api/v1/cases/{case_id}/cti-reports/{report_id}",
		applyMiddleware(http.HandlerFunc(handleUnlinkCaseCTIReport),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/cases",
		applyMiddleware(http.HandlerFunc(handleListReportCases),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/create-case",
		applyMiddleware(http.HandlerFunc(handleCreateCaseFromReport),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))

	// M7-C: Client Relevance Engine (same-client-only).
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/assess",
		applyMiddleware(http.HandlerFunc(handleAssessRelevance),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/cti/reports/{report_id}/relevance/{client_id}",
		applyMiddleware(http.HandlerFunc(handleGetRelevance),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("GET /api/v1/clients/{client_id}/relevant-reports",
		applyMiddleware(http.HandlerFunc(handleListRelevantReports),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/cti/reports/{report_id}/relevance/{client_id}/review",
		applyMiddleware(http.HandlerFunc(handleReviewRelevance),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap,
			csrfWrap))

	// M7-D Phase 1: versioned hypothesis authoring (same-client-only).
	mux.HandleFunc("POST /api/v1/hypotheses",
		applyMiddleware(http.HandlerFunc(handleCreateHypothesisManual),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/hypotheses/from-report",
		applyMiddleware(http.HandlerFunc(handleCreateHypothesisFromReport),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/hypotheses/{hypothesis_id}",
		applyMiddleware(http.HandlerFunc(handleGetHypothesis),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("GET /api/v1/hypotheses/{hypothesis_id}/versions/{version_no}",
		applyMiddleware(http.HandlerFunc(handleGetHypothesisVersion),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("PATCH /api/v1/hypotheses/{hypothesis_id}/versions/{version_no}",
		applyMiddleware(http.HandlerFunc(handleEditHypothesisVersion),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/hypotheses/{hypothesis_id}/submit",
		applyMiddleware(http.HandlerFunc(handleSubmitHypothesisReview),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/hypotheses/{hypothesis_id}/versions/{version_no}/review",
		applyMiddleware(http.HandlerFunc(handleReviewHypothesisVersion),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanReviewHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/hypotheses/{hypothesis_id}/history",
		applyMiddleware(http.HandlerFunc(handleGetHypothesisHistory),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	// Phase 2: Field Intelligence (M7-D Phase 2A).
	mux.HandleFunc("GET /api/v1/qradar/instances",
		applyMiddleware(http.HandlerFunc(handleListQRadarInstances),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/instances",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarInstance),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/instances/{instance_id}",
		applyMiddleware(http.HandlerFunc(handleGetQRadarInstance),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/domains",
		applyMiddleware(http.HandlerFunc(handleListQRadarDomains),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/domains",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarDomain),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/domains/{domain_id}",
		applyMiddleware(http.HandlerFunc(handleGetQRadarDomain),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/log-source-types",
		applyMiddleware(http.HandlerFunc(handleListQRadarLogSourceTypes),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/log-source-types",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarLogSourceType),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/log-source-types/{log_source_type_id}",
		applyMiddleware(http.HandlerFunc(handleGetQRadarLogSourceType),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/log-sources",
		applyMiddleware(http.HandlerFunc(handleListQRadarLogSources),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/log-sources",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarLogSource),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/log-sources/{log_source_id}",
		applyMiddleware(http.HandlerFunc(handleGetQRadarLogSource),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/qids",
		applyMiddleware(http.HandlerFunc(handleListQRadarQIDs),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/qids",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarQID),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/qids/{qid}",
		applyMiddleware(http.HandlerFunc(handleGetQRadarQID),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/field-definitions",
		applyMiddleware(http.HandlerFunc(handleListQRadarFieldDefinitions),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/field-definitions",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarFieldDefinition),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/field-definitions/{field_id}",
		applyMiddleware(http.HandlerFunc(handleGetQRadarFieldDefinition),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/field-mappings",
		applyMiddleware(http.HandlerFunc(handleListQRadarFieldMappings),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/field-mappings",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarFieldMapping),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/field-mappings/{mapping_id}",
		applyMiddleware(http.HandlerFunc(handleGetQRadarFieldMapping),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/field-observations",
		applyMiddleware(http.HandlerFunc(handleListQRadarFieldObservations),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/field-observations",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarFieldObservation),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/field-observations/{observation_id}",
		applyMiddleware(http.HandlerFunc(handleGetQRadarFieldObservation),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/import-batches",
		applyMiddleware(http.HandlerFunc(handleListQRadarImportBatches),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/import-batches",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarImportBatch),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/import-batches/{batch_id}",
		applyMiddleware(http.HandlerFunc(handleGetQRadarImportBatch),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/import-batches/{batch_id}/review",
		applyMiddleware(http.HandlerFunc(handleReviewQRadarImportBatch),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanReviewFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/qradar/import-batches/{batch_id}/publish",
		applyMiddleware(http.HandlerFunc(handlePublishQRadarImportBatch),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanReviewFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/qradar/field-mappings/{mapping_id}/approve",
		applyMiddleware(http.HandlerFunc(handleApproveQRadarFieldMapping),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanReviewFieldIntel),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("GET /api/v1/qradar/import-rows",
		applyMiddleware(http.HandlerFunc(handleListQRadarImportRows),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("POST /api/v1/qradar/import-field-maps",
		applyMiddleware(http.HandlerFunc(handleCreateQRadarImportFieldMap),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/import-field-maps",
		applyMiddleware(http.HandlerFunc(handleListQRadarImportFieldMaps),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	// M7-D Phase 2B-3: AQL draft translation (local worker; never executes).
	mux.HandleFunc("POST /api/v1/sigma-rules/{rule_id}/translations",
		applyMiddleware(http.HandlerFunc(handleCreateDetectionTranslation),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanGenerateAQL),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/sigma-rules/{rule_id}/translations",
		applyMiddleware(http.HandlerFunc(handleListDetectionTranslations),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("GET /api/v1/detection-translations/{translation_id}",
		applyMiddleware(http.HandlerFunc(handleGetDetectionTranslation),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	// M7-D Phase 2B-1 / 2B-2: Sigma ingestion and readiness analysis (no worker).
	mux.HandleFunc("POST /api/v1/detections/sigma",
		applyMiddleware(http.HandlerFunc(handleIngestSigma),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanManageDetections),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/detections/sigma",
		applyMiddleware(http.HandlerFunc(handleListSigmaRules),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("GET /api/v1/detections/sigma/{rule_id}",
		applyMiddleware(http.HandlerFunc(handleGetSigmaRule),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("GET /api/v1/detections/sigma/{rule_id}/scope",
		applyMiddleware(http.HandlerFunc(handleDetectionScope),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("GET /api/v1/qradar/domain-bindings",
		applyMiddleware(http.HandlerFunc(handleListDomainBindings),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	// M7-D Phase 2B-4A: Hunt Plans (reviewed draft bundles; never executed).
	mux.HandleFunc("POST /api/v1/hunt-plans",
		applyMiddleware(http.HandlerFunc(handleCreateHuntPlan),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/hunt-plans",
		applyMiddleware(http.HandlerFunc(handleListHuntPlans),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("GET /api/v1/hunt-plans/{plan_id}",
		applyMiddleware(http.HandlerFunc(handleGetHuntPlan),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/hunt-plans/{plan_id}/items",
		applyMiddleware(http.HandlerFunc(handleAddHuntPlanItem),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/hunt-plans/{plan_id}/submit",
		applyMiddleware(http.HandlerFunc(handleSubmitHuntPlan),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/hunt-plans/{plan_id}/review",
		applyMiddleware(http.HandlerFunc(handleReviewHuntPlan),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanReviewHypothesis),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/hunt-plans/{plan_id}/versions",
		applyMiddleware(http.HandlerFunc(handleCreateHuntPlanVersion),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanCreateHypothesis),
			auditWrap,
			csrfWrap))
	// M7-F Phase 1: manual inventory import and completeness (no QRadar calls).
	mux.HandleFunc("GET /api/v1/qradar/inventory/completeness",
		applyMiddleware(http.HandlerFunc(handleInventoryCompleteness),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("GET /api/v1/qradar/inventory/import-templates/{kind}",
		applyMiddleware(http.HandlerFunc(handleInventoryTemplate),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/inventory/import/preview",
		applyMiddleware(http.HandlerFunc(handleInventoryImportPreview),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("POST /api/v1/qradar/inventory/import/commit",
		applyMiddleware(http.HandlerFunc(handleInventoryImportCommit),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("PUT /api/v1/qradar/domains/{domain_id}/binding",
		applyMiddleware(http.HandlerFunc(handleUpdateDomainBinding),
			requireAuth,
			requirePermission(CanManageQRadarBindings),
			auditWrap,
			csrfWrap))
	mux.HandleFunc("GET /api/v1/qradar/domains/{domain_id}/binding-history",
		applyMiddleware(http.HandlerFunc(handleDomainBindingHistory),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("POST /api/v1/qradar/import-file",
		applyMiddleware(http.HandlerFunc(handleImportQRadarFile),
			requireAuth,
			requirePermission(CanViewCTI),
			requirePermission(CanImportFieldIntel),
			auditWrap,
			csrfWrap))

	// Case read endpoint — returns the authorized case context.
	// Reuses GetCaseContext business logic; no duplication.
	mux.HandleFunc("GET /api/v1/cases/{case_id}",
		applyMiddleware(http.HandlerFunc(handleGetCase),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	// Phase 2: Inventory API
	mux.HandleFunc("GET /api/v1/clients",
		applyMiddleware(http.HandlerFunc(handleListClients),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("POST /api/v1/clients",
		applyMiddleware(http.HandlerFunc(handleCreateClient),
			requireAuth,
			requirePermission(CanManageClients),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("GET /api/v1/sectors",
		applyMiddleware(http.HandlerFunc(handleListSectors),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/inventory/fields",
		applyMiddleware(http.HandlerFunc(handleListGlobalFields),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/inventory/rules",
		applyMiddleware(http.HandlerFunc(handleListDetectionRules),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/inventory/telemetry",
		applyMiddleware(http.HandlerFunc(handleListClientTelemetry),
			requireAuth,
			requirePermission(CanViewCTI),
			tenantMW.RequireTenantAccess,
			auditWrap))

	// QRadar import & query API
	mux.HandleFunc("POST /api/v1/qradar/import",
		applyMiddleware(http.HandlerFunc(handleQRadarImport),
			requireAuth,
			requirePermission(IsAdministrator),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("GET /api/v1/qradar/rules",
		applyMiddleware(http.HandlerFunc(handleQRadarRules),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/rules/{rule_id}",
		applyMiddleware(http.HandlerFunc(handleQRadarRuleDetail),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/building-blocks",
		applyMiddleware(http.HandlerFunc(handleQRadarBuildingBlocks),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/building-blocks/{bb_id}",
		applyMiddleware(http.HandlerFunc(handleQRadarBuildingBlockDetail),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/qradar/fields",
		applyMiddleware(http.HandlerFunc(handleQRadarFields),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	// Phase 4: Multi-Harness Foundation API
	mux.HandleFunc("GET /api/v1/harnesses",
		applyMiddleware(http.HandlerFunc(handleListHarnesses),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("POST /api/v1/harnesses",
		applyMiddleware(http.HandlerFunc(handleCreateHarness),
			requireAuth,
			requirePermission(CanManageClients),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("GET /api/v1/harnesses/{agent_id}",
		applyMiddleware(http.HandlerFunc(handleGetHarness),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("PUT /api/v1/harnesses/{agent_id}",
		applyMiddleware(http.HandlerFunc(handleUpdateHarness),
			requireAuth,
			requirePermission(CanManageClients),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("DELETE /api/v1/harnesses/{agent_id}",
		applyMiddleware(http.HandlerFunc(handleDeleteHarness),
			requireAuth,
			requirePermission(CanManageClients),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("POST /api/v1/harnesses/{agent_id}/health",
		applyMiddleware(http.HandlerFunc(handleHarnessHealth),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/ai/tasks",
		applyMiddleware(http.HandlerFunc(handleListAITasks),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("POST /api/v1/ai/tasks",
		applyMiddleware(http.HandlerFunc(handleCreateAITask),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("GET /api/v1/ai/tasks/{task_id}",
		applyMiddleware(http.HandlerFunc(handleGetAITask),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("POST /api/v1/ai/tasks/{task_id}/execute",
		applyMiddleware(http.HandlerFunc(handleExecuteAITask),
			requireAuth,
			requirePermission(CanCreateCTI),
			auditWrap,
			csrfWrap))

	mux.HandleFunc("GET /api/v1/ai/executions",
		applyMiddleware(http.HandlerFunc(handleListExecutions),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))

	mux.HandleFunc("GET /api/v1/ai/executions/{execution_id}",
		applyMiddleware(http.HandlerFunc(handleGetExecution),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	log.Printf("Registered routes: /api/v1/health, /api/v1/auth/login, /api/v1/auth/logout, /api/v1/auth/me, /api/v1/tenants/{client_id}/cti/reports, /api/v1/clients, /api/v1/sectors, /api/v1/inventory/fields, /api/v1/inventory/rules, /api/v1/inventory/telemetry, /api/v1/qradar/*, /api/v1/harnesses/*, /api/v1/ai/*")

	// Check for dedicated MCP stdio mode.
	// Usage: sentinel-atlas mcp-stdio
	// In this mode, only the MCP server runs on stdio; no HTTP server is started.
	// stdout carries only MCP protocol messages; all diagnostics go to stderr.
	if len(os.Args) > 2 && os.Args[1] == "mcp-stdio" {
		mcpServer := NewMCPServer()
		mcpServer.RegisterMCPTools()
		log.Printf("MCP stdio mode: starting MCP server on stdin/stdout")
		if err := mcpServer.RunStdio(); err != nil {
			slog.Error("MCP server stopped", "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	addr, err := listenAddress(globalConfig)
	if err != nil {
		log.Fatalf("invalid %s: %v", listenAddrEnv, err)
	}
	log.Printf("MSSP Intelligence Workbench starting on %s (secure=%v)", addr, isSecure)
	log.Printf("Mode: on-premise, DB: sqlite, storage: %s", globalConfig.DBPath)
	log.Printf("Registered routes: /api/v1/health, /api/v1/auth/login, /api/v1/auth/logout, /api/v1/auth/me, /api/v1/tenants/{client_id}/cti/reports, /api/v1/clients, /api/v1/sectors, /api/v1/inventory/fields, /api/v1/inventory/rules, /api/v1/inventory/telemetry")

	// Normal HTTP mode: MCP server is NOT started on stdio.
	// The MCP stdio process must be launched separately via "mcp-stdio" subcommand.
	// This ensures the HTTP server does not consume stdin.
	if err := requireM6Schema(); err != nil {
		log.Fatalf("database schema is not ready (%v); run: %s migrate %s", err, os.Args[0], globalConfig.DBPath)
	}
	if err := requireM7DSchema(); err != nil {
		log.Fatalf("database schema is not ready (%v); run: %s migrate %s", err, os.Args[0], globalConfig.DBPath)
	}
	log.Printf("HTTP mode: MCP stdio server not started (use 'mcp-stdio' subcommand)")

    // Stage F: static files from ../frontend. API routes take precedence.
	mux.HandleFunc("GET /api/v1/hypotheses",
		applyMiddleware(http.HandlerFunc(handleListAvailableHypotheses),
			requireAuth,
			requirePermission(CanViewCTI),
			auditWrap))
	mux.HandleFunc("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		frontendDir, err := filepath.Abs(filepath.Join("..", "frontend"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// Clean paths: only serve files inside frontendDir, block traversal.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			http.ServeFile(w, r, filepath.Join(frontendDir, "cases-list.html"))
			return
		}
		if p == "cases" {
			http.ServeFile(w, r, filepath.Join(frontendDir, "cases-list.html"))
			return
		}
		if strings.HasPrefix(p, "case/") {
			http.ServeFile(w, r, filepath.Join(frontendDir, "case-detail.html"))
			return
		}
		if strings.Contains(p, "..") || strings.Contains(p, "\\") {
			http.NotFound(w, r)
			return
		}
		full := filepath.Join(frontendDir, p)
		if rel, err := filepath.Rel(frontendDir, full); err != nil || strings.HasPrefix(rel, "..") {
			http.NotFound(w, r)
			return
		}
		// Directories list files inside; serve their index.html (v3/).
		if strings.HasSuffix(p, "/") || strings.HasSuffix(p, "/index.html") {
			idx := filepath.Join(frontendDir, filepath.Dir(p), "index.html")
			if _, err := os.Stat(idx); err == nil {
				http.ServeFile(w, r, idx)
				return
			}
		}
		// Artifacts live under ../storage and are never served statically.
		http.ServeFile(w, r, full)
	}))

	if err := http.ListenAndServe(addr, proxyTrustMiddleware(trustedProxies, trustedHops, addCORSHeaders(mux))); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func applyMiddleware(handler http.Handler, middlewares ...func(http.Handler) http.Handler) http.HandlerFunc {
	var h http.Handler = handler
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}
}

var requireAuth = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := getSessionFromRequest(r)
		if sessionID == "" {
			writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "not authenticated")
			return
		}

		session, err := globalDB.GetSession(sessionID)
		if err != nil || session == nil {
			writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "invalid or expired session")
			return
		}

		ctx := context.WithValue(r.Context(), sessionCtxKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requirePermission(check PermissionCheck) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session := sessionFromContext(r.Context())
			if session == nil {
				writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
				return
			}

			role, err := globalDB.GetUserRole(session.UserID)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "user not found")
				return
			}

			rp, ok := GetPermission(role)
			if !ok {
				writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "unknown role")
				return
			}

			if !check(rp) {
				writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

var auditWrap = func(next http.Handler) http.Handler {
	return NewAuditMiddleware(globalDB, isSecure).Wrap(next)
}

var csrfWrap = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only validate state-changing methods
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Origin header check
		origin := r.Header.Get("Origin")
		if origin == "" {
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "CSRF validation failed: missing Origin header")
			return
		}
		originValid := false
		for _, allowed := range globalCSRFValidator.allowedOrigins {
			if origin == allowed {
				originValid = true
				break
			}
		}
		if !originValid {
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "CSRF validation failed: invalid Origin header")
			return
		}

		// CSRF token double-submit check (cookie vs header)
		cookie, err := r.Cookie("csrf_token")
		if err != nil {
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "CSRF validation failed: missing CSRF token cookie")
			return
		}
		headerToken := r.Header.Get("X-CSRF-Token")
		if headerToken == "" {
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "CSRF validation failed: missing X-CSRF-Token header")
			return
		}
		if !hmac.Equal([]byte(cookie.Value), []byte(headerToken)) {
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "CSRF validation failed: token mismatch")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	if globalConfig != nil && globalConfig.Origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", globalConfig.Origin)
	}
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Cookie")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"code":"%s","message":"%s"}}`, code, message)
}

func addCORSHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Use the configured origin instead of wildcard (*) when credentials are
		// allowed. A wildcard origin with Access-Control-Allow-Credentials: true
		// is invalid per the CORS spec and is rejected by browsers.
		if globalConfig != nil && globalConfig.Origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", globalConfig.Origin)
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Cookie")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"mssp-workbench","mode":"on-premise","db":"sqlite"}`))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	// Rate limiting: max 5 login attempts per minute per IP. Forwarded addresses
	// are honoured only through a trusted proxy (see proxy_trust.go).
	ip := requestClientIP(r)
	if !globalRateLimiter.allow(ip) {
		writeJSONError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many login attempts, please try again later")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "username and password required")
		return
	}

	result, err := globalDB.Authenticate(req.Username, req.Password)
	if err != nil {
		log.Printf("Authenticate error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "authentication failed")
		return
	}
	log.Printf("Authenticate result: Success=%v, UserID=%s, Role=%s, Error=%s", result.Success, result.UserID, result.Role, result.Error)
	if !result.Success {
		globalAuditLogger.Log(AuditEvent{
			UserID:   req.Username,
			Action:   "auth.login",
			Resource: "/api/v1/auth/login",
			Result:   "failure",
			SourceIP: r.RemoteAddr,
		})
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "invalid credentials")
		return
	}

	clientID := req.ClientID
	if clientID == "" {
		clients, err := globalDB.GetUserAuthorizedClients(result.UserID)
		if err != nil || len(clients) == 0 {
			writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "no authorized clients")
			return
		}
		clientID = clients[0]
	}

	if !CanAccessClient(result.UserID, clientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	session, err := globalDB.CreateSession(result.UserID, clientID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create session")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   result.UserID,
		ClientID: clientID,
		Action:   "auth.login",
		Resource: "/api/v1/auth/login",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	setSessionCookie(w, session.SessionID, secureRequest(r))

	// Set CSRF token cookie (double-submit pattern)
	csrfToken, err := generateCSRFToken()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate CSRF token")
		return
	}
	setCSRFCookie(w, csrfToken, secureRequest(r))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"user":{"id":"%s","username":"%s","role":"%s"},"client_id":"%s","session_id":"%s","csrf_token":"%s"}`,
		result.UserID, req.Username, result.Role, clientID, session.SessionID, csrfToken)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	sessionID := getSessionFromRequest(r)
	if sessionID != "" {
		session, _ := globalDB.GetSession(sessionID)
		if session != nil {
			globalAuditLogger.Log(AuditEvent{
				UserID:   session.UserID,
				ClientID: session.ClientID,
				Action:   "auth.logout",
				Resource: "/api/v1/auth/logout",
				Result:   "success",
				SourceIP: r.RemoteAddr,
			})
		}
		globalDB.DeleteSession(sessionID)
	}

	clearSessionCookie(w)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"logged out"}`))
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	role, err := globalDB.GetUserRole(session.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get user role")
		return
	}

	clients, err := globalDB.GetUserAuthorizedClients(session.UserID)
	if err != nil {
		clients = []string{session.ClientID}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"user":{"id":"%s","role":"%s"},"client_id":"%s","authorized_clients":[%s]}`,
		session.UserID, role, session.ClientID,
		quoteStrings(clients))
}

func handleTenantCTIReports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	clientID := extractClientID(r)
	if clientID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id required")
		return
	}

	if !CanAccessClient(session.UserID, clientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	rows, err := globalDB.Query(`
		SELECT r.report_id, r.title, r.author, r.publication_date, r.collection_date,
		       r.status, r.checksum
		FROM cti_reports r
		WHERE r.client_id = ?
		ORDER BY r.collection_date DESC`, clientID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to query reports")
		return
	}
	defer rows.Close()

	type Report struct {
		ReportID        string `json:"report_id"`
		Title           string `json:"title"`
		Author          string `json:"author"`
		PublicationDate string `json:"publication_date"`
		CollectionDate  string `json:"collection_date"`
		Status          string `json:"status"`
		Checksum        string `json:"checksum"`
	}
	var reports []Report
	for rows.Next() {
		var rep Report
		var pubDate, collDate, author sql.NullString
		if err := rows.Scan(&rep.ReportID, &rep.Title, &author, &pubDate, &collDate,
			&rep.Status, &rep.Checksum); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to scan report")
			return
		}
		if author.Valid {
			rep.Author = author.String
		}
		if pubDate.Valid {
			rep.PublicationDate = pubDate.String
		}
		if collDate.Valid {
			rep.CollectionDate = collDate.String
		}
		reports = append(reports, rep)
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: clientID,
		Action:   "cti.reports.read",
		Resource: fmt.Sprintf("/api/v1/tenants/%s/cti/reports", clientID),
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id": clientID,
		"reports":   reports,
		"count":     len(reports),
	})
}

// handleGetCase returns the authorized context of a research case via HTTP.
// Reuses GetCaseContext business logic — no duplication.
func handleGetCase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	caseID := r.PathValue("case_id")
	if caseID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "case_id required")
		return
	}

	ctx, err := GetCaseContext(caseID, session.UserID)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.read",
		Resource: "/api/v1/cases/" + caseID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ctx)
}

func handleListCases(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	q := r.URL.Query()
	limit, offset := 20, 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 500 {
			writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid limit")
			return
		}
		limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid offset")
			return
		}
		offset = n
	}

	cases, total, err := ListResearchCases(session.UserID, q.Get("status"), q.Get("priority"), q.Get("client_id"), limit, offset)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list cases")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.list",
		Resource: "/api/v1/cases",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"cases":  cases,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func handleCreateCase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	var req struct {
		Title           string `json:"title"`
		Description     string `json:"description"`
		InitialClientID string `json:"initial_client_id"`
		IdempotencyKey  string `json:"idempotency_key"`
		Priority        string `json:"priority"`
		Severity        string `json:"severity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "title required")
		return
	}
	switch req.Priority {
	case "", "P1", "P2", "P3", "P4":
	default:
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid priority")
		return
	}
	switch req.Severity {
	case "", "CRITICAL", "HIGH", "MEDIUM", "LOW":
	default:
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid severity")
		return
	}

	// Idempotency: key is created by the client app once per logical operation
	// and reused on retries. If absent, generate one so the retry contract holds.
	idemKey := req.IdempotencyKey
	if idemKey == "" {
		k, err := GenerateCaseID()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate idempotency key")
			return
		}
		idemKey = k
	}

	// Fast path for retries: existing row with same key.
	var existingID, ownerID string
	var storedHash sql.NullString
	lookupErr := globalDB.QueryRow(`SELECT case_id, owner_id, payload_hash FROM research_cases WHERE idempotency_key = ?`, idemKey).Scan(&existingID, &ownerID, &storedHash)
	if lookupErr == nil {
		if ownerID != session.UserID {
			writeJSONError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "idempotency key belongs to another owner")
			return
		}
		if !storedHash.Valid || !payloadHashMatches(storedHash.String, req.Title, req.Description, req.InitialClientID, req.Priority, req.Severity) {
			writeJSONError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "idempotency key reused with different payload")
			return
		}
		writeCaseResponse(w, r, session, existingID, http.StatusOK)
		return
	}

	caseID, err := CreateResearchCaseEx(session.UserID, req.Title, req.Description, idemKey, req.InitialClientID, req.Priority, req.Severity)
	if err != nil {
		if errors.Is(err, ErrIdempotencyConflict) {
			// Lost a race: re-read and apply the same payload comparison.
			var rid, rowner string
			var rhash sql.NullString
			qerr := globalDB.QueryRow(`SELECT case_id, owner_id, payload_hash FROM research_cases WHERE idempotency_key = ?`, idemKey).Scan(&rid, &rowner, &rhash)
			if qerr != nil || rowner != session.UserID {
				writeJSONError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "idempotency key belongs to another owner")
				return
			}
			if !rhash.Valid || !payloadHashMatches(rhash.String, req.Title, req.Description, req.InitialClientID, req.Priority, req.Severity) {
				writeJSONError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "idempotency key reused with different payload")
				return
			}
			writeCaseResponse(w, r, session, rid, http.StatusOK)
			return
		}
		if errors.Is(err, ErrClientAccessDenied) || errors.Is(err, ErrDraftPermissionDenied) {
			writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized to create case for this client")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create case")
		return
	}

	writeCaseResponse(w, r, session, caseID, http.StatusCreated)
}

func handleTransitionCaseStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	var req struct {
		Status       string `json:"status"`
		ClosedReason string `json:"closed_reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Status == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "status required")
		return
	}
	if err := TransitionCaseStatus(caseID, session.UserID, req.Status, req.ClosedReason); err != nil {
		switch {
		case errors.Is(err, ErrCaseArchived), errors.Is(err, ErrInvalidTransition):
			writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "transition not allowed from current status")
		case errors.Is(err, ErrDraftPermissionDenied):
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions for this transition")
		case errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrCaseNotFound):
			writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		default:
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to transition case")
		}
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.status",
		Resource: "/api/v1/cases/" + caseID + "/status",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	writeCaseResponse(w, r, session, caseID, http.StatusOK)
}

func handleAddCaseParticipant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	var req struct {
		UserID     string `json:"user_id"`
		RoleInCase string `json:"role_in_case"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "user_id required")
		return
	}
	if err := AddCaseParticipant(caseID, session.UserID, req.UserID, req.RoleInCase); err != nil {
		switch {
		case errors.Is(err, ErrNotCaseOwner), errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrCaseNotFound):
			writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "only the case owner may manage participants")
		case errors.Is(err, ErrCaseArchived), errors.Is(err, ErrInvalidTransition):
			writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "participant change not allowed")
		case errors.Is(err, ErrParticipantNotFound):
			writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		default:
			if strings.HasPrefix(err.Error(), "invalid role_in_case") || strings.HasPrefix(err.Error(), "user_id is required") {
				writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to add participant")
		}
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.participant.add",
		Resource: "/api/v1/cases/" + caseID + "/participants",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	parts, _ := ListCaseParticipants(caseID, session.UserID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"participants": parts, "count": len(parts)})
}

func handleListCaseParticipants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	parts, err := ListCaseParticipants(caseID, session.UserID)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"participants": parts, "count": len(parts)})
}

func handleRemoveCaseParticipant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	target := r.PathValue("user_id")
	if err := RemoveCaseParticipant(caseID, session.UserID, target); err != nil {
		switch {
		case errors.Is(err, ErrNotCaseOwner), errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrCaseNotFound):
			writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "only the case owner may manage participants")
		case errors.Is(err, ErrParticipantNotFound):
			writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "participant not found")
		case errors.Is(err, ErrCaseArchived):
			writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "case is archived")
		default:
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to remove participant")
		}
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.participant.remove",
		Resource: "/api/v1/cases/" + caseID + "/participants/" + target,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

func handleReviewArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	artifactID := r.PathValue("artifact_id")
	var req struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}
	result, err := ReviewCaseArtifact(caseID, session.UserID, artifactID, req.Decision, req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, ErrSchemaNotReady):
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
		case errors.Is(err, ErrInvalidReviewDecision):
			writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid decision")
		case errors.Is(err, ErrReviewPermissionDenied), errors.Is(err, ErrClientAccessDenied), errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrCaseNotFound):
			writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		case errors.Is(err, ErrCaseArchived), errors.Is(err, ErrInvalidTransition):
			writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "cannot review this artifact")
		default:
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to review artifact")
		}
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "artifact.review",
		Resource: "/api/v1/cases/" + caseID + "/artifacts/" + artifactID + "/review",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	if result.ClientID != "" {
		// Audit must never carry private CLIENT metadata for unauthorized users;
		// this log line is server-side only, but keep client scope server-side.
		_ = result.ClientID
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

func handleCreateNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	var req struct {
		NoteText        string `json:"note_text"`
		NoteType        string `json:"note_type"`
		VisibilityScope string `json:"visibility_scope"`
		ClientID        string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}
	noteID, err := CreateCaseNote(caseID, session.UserID, req.NoteText, req.NoteType, req.VisibilityScope, req.ClientID)
	if err != nil {
		switch {
		case errors.Is(err, ErrSchemaNotReady):
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
		case errors.Is(err, ErrClientAccessDenied), errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrCaseNotFound), errors.Is(err, ErrGlobalArtifactClientData):
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "forbidden")
		case errors.Is(err, ErrCaseArchived):
			writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "case is archived")
		default:
			if err.Error() == "note_text is required" || strings.HasPrefix(err.Error(), "invalid note_type") || strings.HasPrefix(err.Error(), "invalid visibility_scope") || strings.HasPrefix(err.Error(), "client_id") {
				writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create note")
		}
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.note.create",
		Resource: "/api/v1/cases/" + caseID + "/notes",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"note_id": noteID, "case_id": caseID})
}

func handleListNotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	limit, offset := parseLimitOffset(r)
	notes, total, err := ListCaseNotes(caseID, session.UserID, limit, offset)
	if err != nil {
		if errors.Is(err, ErrSchemaNotReady) {
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
			return
		}
		writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.note.list",
		Resource: "/api/v1/cases/" + caseID + "/notes",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"notes": notes, "total": total, "limit": limit, "offset": offset,
	})
}

func handleListAvailableHypotheses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	clientID := r.URL.Query().Get("client_id")
	limit, offset := parseLimitOffset(r)
	rows, total, err := ListAvailableHypotheses(session.UserID, clientID, limit, offset)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list hypotheses")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "hypothesis.list",
		Resource: "/api/v1/hypotheses",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hypotheses": rows, "total": total, "limit": limit, "offset": offset,
	})
}

func handleListActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	limit, offset := parseLimitOffset(r)
	rows, total, err := ListVisibleCaseActivityPaged(caseID, session.UserID, limit, offset)
	if err != nil {
		if errors.Is(err, ErrSchemaNotReady) {
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
			return
		}
		writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.activity.list",
		Resource: "/api/v1/cases/" + caseID + "/activity",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"activity": rows, "total": total, "limit": limit, "offset": offset,
	})
}

func handleLinkHypothesis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	hypID := r.PathValue("hypothesis_id")
	if err := LinkCaseHypothesis(caseID, session.UserID, hypID); err != nil {
		switch {
		case errors.Is(err, ErrSchemaNotReady):
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
		case errors.Is(err, ErrHypothesisAccessDenied), errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrCaseNotFound):
			writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		case errors.Is(err, ErrCaseArchived):
			writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "case is archived")
		default:
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to link hypothesis")
		}
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.hypothesis.link",
		Resource: "/api/v1/cases/" + caseID + "/hypotheses/" + hypID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"case_id": caseID, "hypothesis_id": hypID, "status": "linked"})
}

func handleUnlinkHypothesis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	hypID := r.PathValue("hypothesis_id")
	if err := UnlinkCaseHypothesis(caseID, session.UserID, hypID); err != nil {
		switch {
		case errors.Is(err, ErrSchemaNotReady):
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
		case errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrCaseNotFound):
			writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		case errors.Is(err, ErrCaseArchived):
			writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "case is archived")
		default:
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to unlink hypothesis")
		}
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.hypothesis.unlink",
		Resource: "/api/v1/cases/" + caseID + "/hypotheses/" + hypID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"case_id": caseID, "hypothesis_id": hypID, "status": "unlinked"})
}

func handleListHypotheses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	limit, offset := parseLimitOffset(r)
	rows, total, err := ListLinkedHypotheses(caseID, session.UserID, limit, offset)
	if err != nil {
		if errors.Is(err, ErrSchemaNotReady) {
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
			return
		}
		writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.hypothesis.list",
		Resource: "/api/v1/cases/" + caseID + "/hypotheses",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"hypotheses": rows, "total": total, "limit": limit, "offset": offset,
	})
}

func handleReviewHypothesis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	hypID := r.PathValue("hypothesis_id")
	var req struct {
		ClientID string `json:"client_id"`
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}
	result, err := ReviewCaseHypothesis(caseID, session.UserID, hypID, req.ClientID, req.Decision, req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, ErrSchemaNotReady):
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
		case errors.Is(err, ErrInvalidReviewDecision):
			writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid decision")
		case errors.Is(err, ErrReviewPermissionDenied), errors.Is(err, ErrHypothesisAccessDenied), errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrCaseNotFound):
			writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		case errors.Is(err, ErrCaseArchived):
			writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "case is archived")
		default:
			if strings.HasPrefix(err.Error(), "client_id is required") {
				writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to review hypothesis")
		}
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.hypothesis.review",
		Resource: "/api/v1/cases/" + caseID + "/hypotheses/" + hypID + "/review",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

func handleCreateInvestigation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	var req struct {
		HypothesisID    string `json:"hypothesis_id"`
		ClientID        string `json:"client_id"`
		TimeRange       string `json:"time_range"`
		Evidence        string `json:"evidence"`
		AnalystFindings string `json:"analyst_findings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}
	if req.HypothesisID == "" || req.ClientID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "hypothesis_id and client_id required")
		return
	}
	inv, err := CreateCaseInvestigation(caseID, session.UserID, req.HypothesisID, req.ClientID, req.TimeRange, req.Evidence, req.AnalystFindings)
	if err != nil {
		switch {
		case errors.Is(err, ErrSchemaNotReady):
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
		case errors.Is(err, ErrInvestigationClientDenied), errors.Is(err, ErrCaseAccessDenied), errors.Is(err, ErrCaseNotFound), errors.Is(err, ErrDraftPermissionDenied):
			writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		case errors.Is(err, ErrCaseArchived):
			writeJSONError(w, http.StatusConflict, "INVALID_TRANSITION", "case is archived")
		default:
			if strings.HasPrefix(err.Error(), "client_id is required") {
				writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create investigation")
		}
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.investigation.create",
		Resource: "/api/v1/cases/" + caseID + "/investigations",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(inv)
}

func handleListInvestigations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	caseID := r.PathValue("case_id")
	limit, offset := parseLimitOffset(r)
	rows, total, err := ListCaseInvestigations(caseID, session.UserID, limit, offset)
	if err != nil {
		if errors.Is(err, ErrSchemaNotReady) {
			writeJSONError(w, http.StatusServiceUnavailable, "SCHEMA_NOT_READY", "M6 schema not applied")
			return
		}
		writeJSONError(w, http.StatusForbidden, "CASE_ACCESS_DENIED", "access denied")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.investigation.list",
		Resource: "/api/v1/cases/" + caseID + "/investigations",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"investigations": rows, "total": total, "limit": limit, "offset": offset,
	})
}

func seedStageFDB(dbPath string) error {
	// SAFETY: never seed into the production/working SQLite. The working DB
	// is identified by the conventional base name "workbench.db" or by the
	// exact absolute path of the default WORKBENCH_DB_PATH. Violations are
	// refused with an error before opening the file.
	if filepath.Base(dbPath) == "workbench.db" {
		return fmt.Errorf("refusing to seed production database (workbench.db)")
	}
	if abs, err := filepath.Abs(dbPath); err == nil {
		def, _ := filepath.Abs(filepath.Join("..", "storage", "workbench.db"))
		if abs == def {
			return fmt.Errorf("refusing to seed production database (default path)")
		}
	}
	// Refuse to overwrite a database that already contains non-synthetic data.
	if _, err := os.Stat(dbPath); err == nil {
		if st, _ := os.Stat(dbPath); st != nil && st.Size() > 0 {
			db0, err0 := sql.Open("sqlite3", dbPath)
			if err0 == nil {
				var n int
				if err0 := db0.QueryRow(`SELECT COUNT(*) FROM users WHERE user_id NOT LIKE 'user-%' AND user_id NOT LIKE 'usr-%'`).Scan(&n); err0 == nil && n > 0 {
					db0.Close()
					return fmt.Errorf("refusing to overwrite database with existing user data: %s", dbPath)
				}
				db0.Close()
			}
		}
	}
	// Open fresh file DB and apply full M1-M6 schema (0001-0005).
	// We cannot use OpenDB here because it intentionally does not seed and
	// only applies 0001-0002.
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=1&_busy_timeout=30000&_journal_mode=WAL")
	if err != nil {
		return fmt.Errorf("opening db: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := runMigration(db, "migrations/0001_initial.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0002_qradar_inventory.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0003_evidence_graph.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0004_p0_mcp_case.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0005_m6_case_workspace.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0006_cti_ingestion.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0007_case_cti_reports.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0008_relevance.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0009_relevance_eval_time.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0010_hunt_hypothesis.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0011_field_intelligence.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0012_field_intel_hardening.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0013_field_intel_review_history.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0014_import_identity_scope.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0015_qradar_domain_bindings.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0016_domain_binding_update_guards.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0017_sigma_detection_ingestion.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0018_detection_translations.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0019_hunt_plans.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0020_hunt_plan_item_integrity.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0021_hunt_plan_item_binding_owner.sql"); err != nil {
		return err
	}
	if err := runMigration(db, "migrations/0022_manual_inventory_provenance.sql"); err != nil {
		return err
	}
	if err := createM1Tables(db); err != nil {
		return err
	}
	// Synthetic seeding for this isolated file only.
	if err := seedTestData(db); err != nil {
		return fmt.Errorf("seed test data: %w", err)
	}
	gDB := &DB{db}
	// Ensure user_authorized_clients grants exist for UI testing.
	for _, g := range []struct{ id, uid, cid string }{
		{"stagef-grant-alpha-alpha", "user-analyst-alpha", "client-alpha"},
		{"stagef-grant-beta-beta", "user-analyst-beta", "client-beta"},
		{"stagef-grant-admin-alpha", "user-admin", "client-alpha"},
		{"stagef-grant-reviewer-alpha", "user-reviewer", "client-alpha"},
	} {
		if _, err := gDB.DB.Exec(`INSERT OR IGNORE INTO user_authorized_clients (grant_id, user_id, client_id) VALUES (?, ?, ?)`, g.id, g.uid, g.cid); err != nil {
			return err
		}
	}
	// Synthetic cases + hypotheses for browser workflow.
	globalDB = gDB
	c1, err := CreateResearchCase("user-analyst-alpha", "Suspicious PowerShell Activity", "Synthetic Stage F case", "stagef-idem-001", "client-alpha")
	if err != nil {
		return fmt.Errorf("synthetic case 1: %w", err)
	}
	if _, err := gDB.DB.Exec(`INSERT OR IGNORE INTO hunt_hypotheses (hypothesis_id, client_id, title, description, status, created_at, updated_at)
		VALUES ('hyp-stagef-alpha-1','client-alpha','PowerShell Hunt','Synthetic hunt hypothesis','DRAFT',datetime('now'),datetime('now'))`); err != nil {
		return err
	}
	if err := LinkCaseHypothesis(c1, "user-analyst-alpha", "hyp-stagef-alpha-1"); err != nil {
		return fmt.Errorf("link synthetic hypothesis: %w", err)
	}
	c2, err := CreateResearchCase("user-analyst-beta", "Beta Private Case", "Synthetic beta case", "stagef-idem-002", "client-beta")
	if err != nil {
		return fmt.Errorf("synthetic case 2: %w", err)
	}
	_ = c2
	if _, err := CreateCaseNote(c1, "user-analyst-alpha", "Global observation for Stage F.", "observation", "GLOBAL", ""); err != nil {
		return err
	}
	if _, err := CreateCaseNote(c1, "user-analyst-alpha", "Alpha-only note body.", "finding", "CLIENT", "client-alpha"); err != nil {
		return err
	}
	// Synthetic M7-D Phase 2A field intelligence for client-alpha (isolated file only).
	for _, stmt := range []string{
		`INSERT OR IGNORE INTO qradar_instances (instance_id, client_id, instance_name, host) VALUES ('qi-stagef-alpha','client-alpha','QRadar-Alpha','qr-alpha.alpha.internal')`,
		`INSERT OR IGNORE INTO qradar_domains (domain_id, instance_id, domain_name, domain_type, native_qradar_domain_id, native_id_status, native_id_source) VALUES ('qd-stagef-alpha','qi-stagef-alpha','Corporate','production','5','VERIFIED','SEED_SYNTHETIC')`,
		`INSERT OR IGNORE INTO qradar_domain_bindings (binding_id, domain_id, instance_id, client_id, binding_kind, verification_status, inferred_client_id, revision) VALUES ('qdb-stagef-alpha','qd-stagef-alpha','qi-stagef-alpha',NULL,'UNASSIGNED','UNVERIFIED','client-alpha',1)`,
		`INSERT OR IGNORE INTO qradar_domain_binding_history (history_id, binding_id, domain_id, instance_id, native_qradar_domain_id, previous_kind, previous_client_id, previous_status, new_kind, new_client_id, new_status, actor_id, evidence_reference, revision) VALUES ('qdbh-stagef-alpha','qdb-stagef-alpha','qd-stagef-alpha','qi-stagef-alpha',NULL,'UNASSIGNED',NULL,'UNVERIFIED','UNASSIGNED',NULL,'UNVERIFIED','user-admin','domain created; binding unverified pending confirmation',1)`,
		`UPDATE qradar_domain_bindings SET client_id='client-alpha', binding_kind='CLIENT', verification_status='VERIFIED', verified_by='user-admin', verified_at=datetime('now'), evidence_reference='synthetic stage-f seed: domain 5 confirmed by administrator', revision=2, updated_at=datetime('now') WHERE domain_id='qd-stagef-alpha' AND verification_status='UNVERIFIED'`,
		`INSERT OR IGNORE INTO qradar_domain_binding_history (history_id, binding_id, domain_id, instance_id, native_qradar_domain_id, previous_kind, previous_client_id, previous_status, new_kind, new_client_id, new_status, actor_id, evidence_reference, revision) VALUES ('qdbh-stagef-alpha-2','qdb-stagef-alpha','qd-stagef-alpha','qi-stagef-alpha','5','UNASSIGNED',NULL,'UNVERIFIED','CLIENT','client-alpha','VERIFIED','user-admin','synthetic stage-f seed: domain 5 confirmed by administrator',2)`,
		`INSERT OR IGNORE INTO qradar_domains (domain_id, instance_id, domain_name, domain_type) VALUES ('qd-stagef-dmz','qi-stagef-alpha','DMZ (legacy, unconfirmed)','production')`,
		`INSERT OR IGNORE INTO qradar_domain_bindings (binding_id, domain_id, instance_id, client_id, binding_kind, verification_status, inferred_client_id, revision) VALUES ('qdb-stagef-dmz','qd-stagef-dmz','qi-stagef-alpha',NULL,'UNASSIGNED','UNVERIFIED','client-beta',1)`,
		`INSERT OR IGNORE INTO qradar_domain_binding_history (history_id, binding_id, domain_id, instance_id, previous_kind, previous_status, new_kind, new_status, actor_id, evidence_reference, revision) VALUES ('qdbh-stagef-dmz','qdb-stagef-dmz','qd-stagef-dmz','qi-stagef-alpha','UNASSIGNED','UNVERIFIED','UNASSIGNED','UNVERIFIED','user-admin','migrated from legacy attribution; native id not verified',1)`,
		`INSERT OR IGNORE INTO qradar_log_source_types (log_source_type_id, domain_id, type_name) VALUES ('qlst-stagef-win','qd-stagef-alpha','Microsoft Windows Security Event Log')`,
		`INSERT OR IGNORE INTO qradar_log_sources (log_source_id, log_source_type_id, status, data_provenance) VALUES ('qls-stagef-win','qlst-stagef-win','CONNECTED','synthetic import')`,
		`INSERT OR IGNORE INTO qradar_qids (qid, log_source_id, event_name, native_event_id) VALUES ('qid-stagef-4698','qls-stagef-win','Scheduled Task Created','4698')`,
		`INSERT OR IGNORE INTO qradar_field_definitions (field_id, client_id, domain_id, field_name, field_origin, data_type, cep_identifier, supported_event_scope, aql_field_expression) VALUES ('qfd-stagef-eventid','client-alpha','qd-stagef-alpha','EventID','system','integer','event_id','4698','event_id')`,
		`INSERT OR IGNORE INTO qradar_field_mappings (mapping_id, client_id, domain_id, raw_source_field, target_cep_field, semantic_alias, applicable_dsm, applicable_event, mapping_version, origin) VALUES ('qfm-stagef-eventcode','client-alpha','qd-stagef-alpha','EventCode','event_id','event_id','Microsoft Windows Security Event Log','4698','1','auto')`,
		`INSERT OR IGNORE INTO qradar_field_observations (observation_id, client_id, domain_id, field_id, field_present_in_raw, qradar_property_displayed, extracted_value_present, aql_verification_status, evidence_reference) VALUES ('qfo-stagef-eventid','client-alpha','qd-stagef-alpha','qfd-stagef-eventid',1,1,1,'UNVERIFIED','synthetic raw event row 1')`,
		`INSERT OR IGNORE INTO qradar_import_batches (batch_id, client_id, domain_id, batch_name, source_type, file_hash, imported_by, processing_status, parser_version, redaction_version, parsed_rows, redacted_values) VALUES ('qib-stagef-01','client-alpha','qd-stagef-alpha','Synthetic Windows Export 2026-01','windows_kev','sha256:stagef-synthetic-01','user-analyst-alpha','MAPPED','parse-1/windows','redact-1',1,3)`,
	} {
		if _, err := gDB.DB.Exec(stmt); err != nil {
			return fmt.Errorf("synthetic field intelligence: %w", err)
		}
	}
	log.Printf("seed-stagef: created synthetic DB at %s (cases: %s, %s)", dbPath, c1, c2)
	return nil
}

func parseLimitOffset(r *http.Request) (int, int) {
	q := r.URL.Query()
	limit, offset := 20, 0
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

func sqlNullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func writeCaseResponse(w http.ResponseWriter, r *http.Request, session *Session, caseID string, status int) {
	var caseObj ResearchCase
	var description sql.NullString
	err := globalDB.QueryRow(`SELECT case_id, idempotency_key, title, description, owner_id, status, created_at, updated_at
		FROM research_cases WHERE case_id = ?`, caseID).
		Scan(&caseObj.CaseID, &caseObj.IdempotencyKey, &caseObj.Title, &description, &caseObj.OwnerID, &caseObj.Status, &caseObj.CreatedAt, &caseObj.UpdatedAt)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load created case")
		return
	}
	caseObj.Description = description.String

	var prio, sev sql.NullString
	_ = globalDB.QueryRow(`SELECT priority, severity FROM research_cases WHERE case_id = ?`, caseID).Scan(&prio, &sev)

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "case.create",
		Resource: "/api/v1/cases",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"case_id":         caseObj.CaseID,
		"idempotency_key": caseObj.IdempotencyKey,
		"title":           caseObj.Title,
		"description":     caseObj.Description,
		"owner_id":        caseObj.OwnerID,
		"status":          caseObj.Status,
		"priority":        prio.String,
		"severity":        sev.String,
		"created_at":      caseObj.CreatedAt,
		"updated_at":      caseObj.UpdatedAt,
	})
}

func sessionFromContext(ctx context.Context) *Session {
	s, ok := ctx.Value(sessionCtxKey).(*Session)
	if !ok {
		return nil
	}
	return s
}

func quoteStrings(strs []string) string {
	result := make([]string, len(strs))
	for i, s := range strs {
		result[i] = strconv.Quote(s)
	}
	return strings.Join(result, ",")
}

// --- Phase 2: Inventory API Handlers ---

func handleListClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	clients, err := globalDB.ListClients(session.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list clients")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
	})
}

func handleCreateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	var req struct {
		ClientID   string `json:"client_id"`
		ClientName string `json:"client_name"`
		Status     string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}

	if req.ClientID == "" || req.ClientName == "" || req.Status == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id, client_name, and status required")
		return
	}

	// Check if client already exists
	existingClients, err := globalDB.ListClients(session.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check existing clients")
		return
	}
	for _, c := range existingClients {
		if c.ClientID == req.ClientID {
			writeJSONError(w, http.StatusConflict, "DUPLICATE_CLIENT", "client already exists")
			return
		}
	}

	if err := globalDB.CreateClient(req.ClientID, req.ClientName, req.Status); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create client")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: req.ClientID,
		Action:   "client.create",
		Resource: "/api/v1/clients",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"client_id":"%s","client_name":"%s","status":"%s"}`,
		req.ClientID, req.ClientName, req.Status)
}

func handleListSectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	sectors, err := globalDB.ListSectors()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list sectors")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sectors": sectors,
		"count":   len(sectors),
	})
}

func handleListGlobalFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	fields, err := globalDB.ListGlobalFields()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list fields")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"fields": fields,
		"count":  len(fields),
	})
}

func handleListDetectionRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	rules, err := globalDB.ListDetectionRules()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list detection rules")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": rules,
		"count": len(rules),
	})
}

func handleListClientTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	clientID := extractClientID(r)
	if clientID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id required")
		return
	}

	if !CanAccessClient(session.UserID, clientID) {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this client")
		return
	}

	statuses, err := globalDB.ListClientTelemetry(clientID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list telemetry")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: clientID,
		Action:   "client_telemetry.read",
		Resource: fmt.Sprintf("/api/v1/inventory/telemetry?client_id=%s", clientID),
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"client_id": clientID,
		"telemetry": statuses,
		"count":     len(statuses),
	})
}

// --- QRadar handlers ---

func handleQRadarImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid multipart form")
		return
	}
	form := r.MultipartForm
	if form == nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "no files uploaded")
		return
	}
	var uploaded []*multipart.FileHeader
	for _, fhs := range form.File {
		uploaded = append(uploaded, fhs...)
	}
	if len(uploaded) == 0 {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "no files uploaded")
		return
	}

	imported := map[string]int{"rules": 0, "shared_bbs": 0, "fields": 0}
	var errs []string
	for _, fh := range uploaded {
		f, err := fh.Open()
		if err != nil {
			errs = append(errs, fmt.Sprintf("open %s: %v", fh.Filename, err))
			continue
		}
		tmp, err := os.CreateTemp("", "qradar-*.yaml")
		if err != nil {
			f.Close()
			errs = append(errs, fmt.Sprintf("temp %s: %v", fh.Filename, err))
			continue
		}
		if _, err := io.Copy(tmp, f); err != nil {
			tmp.Close()
			f.Close()
			errs = append(errs, fmt.Sprintf("copy %s: %v", fh.Filename, err))
			continue
		}
		tmp.Close()
		f.Close()

		// detect type
		data, _ := os.ReadFile(tmp.Name())
		text := strings.ToLower(string(data))
		name := strings.ToLower(fh.Filename)
		var fn func(*DB, string) error
		var key string
		if strings.Contains(name, "shared") || strings.Contains(text, "shared_building_blocks:") {
			fn = ImportSharedBBs
			key = "shared_bbs"
		} else if strings.Contains(name, "field") || (strings.Contains(text, "custom_fields:") && !strings.Contains(text, "\nrules:")) {
			fn = ImportCustomFields
			key = "fields"
		} else {
			fn = ImportQRadarRules
			key = "rules"
		}
		if err := fn(globalDB, tmp.Name()); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", fh.Filename, err))
		} else {
			imported[key]++
		}
		os.Remove(tmp.Name())
	}

	rules, _ := globalDB.ListQRadarRules("", "", "")
	bbs, _ := globalDB.ListBuildingBlocks()
	fields, _ := globalDB.ListQRadarFields("", "")

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		Action:   "qradar.import",
		Resource: "/api/v1/qradar/import",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"imported_files":        imported,
		"rules_count":           len(rules),
		"building_blocks_count": len(bbs),
		"fields_count":          len(fields),
		"errors":                errs,
	})
}

func handleQRadarRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	q := r.URL.Query()
	rules, err := globalDB.ListQRadarRules(q.Get("criticality"), q.Get("log_source"), q.Get("mitre_technique"))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list qradar rules")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		Action:   "qradar.rules.read",
		Resource: "/api/v1/qradar/rules",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": rules,
		"count": len(rules),
	})
}

func handleQRadarRuleDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	ruleID := r.PathValue("rule_id")
	rule, err := globalDB.GetQRadarRule(ruleID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get rule")
		return
	}
	if rule == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "rule not found")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		Action:   "qradar.rule.read",
		Resource: "/api/v1/qradar/rules/" + ruleID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(rule)
}

func handleQRadarBuildingBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	bbs, err := globalDB.ListBuildingBlocks()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list building blocks")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		Action:   "qradar.building_blocks.read",
		Resource: "/api/v1/qradar/building-blocks",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"building_blocks": bbs,
		"count":           len(bbs),
	})
}

func handleQRadarBuildingBlockDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	bbID := r.PathValue("bb_id")
	bb, err := globalDB.GetBuildingBlock(bbID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get building block")
		return
	}
	if bb == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "building block not found")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		Action:   "qradar.building_block.read",
		Resource: "/api/v1/qradar/building-blocks/" + bbID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(bb)
}

func handleQRadarFields(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	q := r.URL.Query()
	fields, err := globalDB.ListQRadarFields(q.Get("availability"), q.Get("log_source"))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list qradar fields")
		return
	}
	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		Action:   "qradar.fields.read",
		Resource: "/api/v1/qradar/fields",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"fields": fields,
		"count":  len(fields),
	})
}

// --- Phase 4: Multi-Harness Foundation Handlers ---

func handleListHarnesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	agents, err := globalDB.ListAgents()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list harnesses")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "harness.list",
		Resource: "/api/v1/harnesses",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"harnesses": agents,
		"count":     len(agents),
	})
}

func handleCreateHarness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	var info AgentInfo
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}
	if info.AgentID == "" || info.AgentName == "" || info.HarnessType == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "agent_id, agent_name, and harness_type required")
		return
	}

	if err := globalDB.CreateAgent(info); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create harness")
		return
	}
	SetAgentInfo(info)

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "harness.create",
		Resource: "/api/v1/harnesses",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(info)
}

func handleGetHarness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	agentID := r.PathValue("agent_id")
	info, err := globalDB.GetAgent(agentID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get harness")
		return
	}
	if info == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "harness not found")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "harness.read",
		Resource: "/api/v1/harnesses/" + agentID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(info)
}

func handleUpdateHarness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	agentID := r.PathValue("agent_id")
	var info AgentInfo
	if err := json.NewDecoder(r.Body).Decode(&info); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}
	info.AgentID = agentID

	if err := globalDB.CreateAgent(info); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update harness")
		return
	}
	SetAgentInfo(info)

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "harness.update",
		Resource: "/api/v1/harnesses/" + agentID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(info)
}

func handleDeleteHarness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	agentID := r.PathValue("agent_id")
	if _, err := globalDB.GetAgent(agentID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check harness")
		return
	}

	if err := globalDB.UpdateAgentStatus(agentID, "deleted"); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete harness")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "harness.delete",
		Resource: "/api/v1/harnesses/" + agentID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func handleHarnessHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	agentID := r.PathValue("agent_id")
	adapter := GetAdapter(agentID)
	if adapter == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "no adapter registered for this harness")
		return
	}

	// Check adapter health (non-blocking: just verify adapter is registered)
	ctx := r.Context()
	if err := adapter.Health(ctx); err != nil {
		globalAuditLogger.Log(AuditEvent{
			UserID:   session.UserID,
			ClientID: session.ClientID,
			Action:   "harness.health",
			Resource: "/api/v1/harnesses/" + agentID + "/health",
			Result:   "failure",
			SourceIP: r.RemoteAddr,
		})
		writeJSONError(w, http.StatusServiceUnavailable, "HEALTH_CHECK_FAILED", err.Error())
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "harness.health",
		Resource: "/api/v1/harnesses/" + agentID + "/health",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func handleListAITasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	clientID := session.ClientID
	tasks, err := globalDB.ListAITasks(clientID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list AI tasks")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "ai.task.list",
		Resource: "/api/v1/ai/tasks",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks": tasks,
		"count": len(tasks),
	})
}

func handleCreateAITask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	var task AITask
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
		return
	}
	if task.TaskID == "" || task.TaskType == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "task_id and task_type required")
		return
	}
	task.ClientID = session.ClientID
	task.Status = "pending"

	if err := globalDB.CreateAITask(&task); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create AI task")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "ai.task.create",
		Resource: "/api/v1/ai/tasks",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(task)
}

func handleGetAITask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	taskID := r.PathValue("task_id")
	task, err := globalDB.GetAITask(taskID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get AI task")
		return
	}
	if task == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "AI task not found")
		return
	}
	if task.ClientID != session.ClientID {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this task")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "ai.task.read",
		Resource: "/api/v1/ai/tasks/" + taskID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(task)
}

func handleExecuteAITask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	taskID := r.PathValue("task_id")
	task, err := globalDB.GetAITask(taskID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get AI task")
		return
	}
	if task == nil {
		writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "AI task not found")
		return
	}
	if task.ClientID != session.ClientID {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this task")
		return
	}

	// Human-in-the-Loop: tasks requiring human review cannot be auto-executed
	if task.HumanReviewRequired {
		writeJSONError(w, http.StatusForbidden, "HUMAN_REVIEW_REQUIRED", "task requires explicit human approval before execution")
		return
	}

	// Find a suitable harness for this task type
	var selectedAdapter HarnessAdapter
	var selectedAgentID string
	for _, agentID := range ListAdapters() {
		info := GetAgentInfo(agentID)
		if info == nil || (info.Status != "healthy" && info.Status != "running") {
			continue
		}
		adapter := GetAdapter(agentID)
		if adapter == nil {
			continue
		}
		// Get user role from trusted server-side session data
		userRole, err := globalDB.GetUserRole(session.UserID)
		if err != nil {
			continue
		}
		// Check harness authorization: user identity, role, action, client access, task ownership,
		// harness permission profile, allowed_clients, exact required capability
		if !CheckHarnessAuthorization(session.UserID, userRole, "execute", agentID, task.ClientID, task.TaskType) {
			continue
		}
		selectedAdapter = adapter
		selectedAgentID = agentID
		break
	}

	if selectedAdapter == nil {
		writeJSONError(w, http.StatusBadRequest, "NO_HARNESS_AVAILABLE", "no healthy harness available for this task type")
		return
	}

	executionID := fmt.Sprintf("exec-%d", time.Now().UnixNano())
	startTime := time.Now()

	input := &ExecutionInput{
		TaskID:     task.TaskID,
		TaskType:   task.TaskType,
		InputData:  task.InputData,
		Parameters: task.Parameters,
		ClientID:   task.ClientID,
	}

	output, err := selectedAdapter.Execute(r.Context(), input)
	if err != nil {
		globalDB.UpdateAITaskStatus(taskID, "failed")
		exec := &AITaskExecution{
			ExecutionID: executionID,
			TaskID:      task.TaskID,
			HarnessID:   selectedAgentID,
			StartTime:   startTime.Format(time.RFC3339),
			EndTime:     time.Now().Format(time.RFC3339),
			Status:      "failed",
			Error:       err.Error(),
		}
		globalDB.CreateAITaskExecution(exec)
		globalDB.CreateAITaskExecutionEvent(executionID, "execution_failed", err.Error())

		globalAuditLogger.Log(AuditEvent{
			UserID:   session.UserID,
			ClientID: session.ClientID,
			Action:   "ai.task.execute",
			Resource: "/api/v1/ai/tasks/" + taskID + "/execute",
			Result:   "failure",
			SourceIP: r.RemoteAddr,
		})
		writeJSONError(w, http.StatusInternalServerError, "EXECUTION_FAILED", err.Error())
		return
	}

	globalDB.UpdateAITaskStatus(taskID, "completed")
	exec := &AITaskExecution{
		ExecutionID:    executionID,
		TaskID:         task.TaskID,
		HarnessID:      selectedAgentID,
		ModelProvider:  "octop",
		ModelName:      "octop-1.0",
		StartTime:      startTime.Format(time.RFC3339),
		EndTime:        output.EndedAt,
		Status:         output.Status,
		Error:          output.Errors,
		OutputReference: output.ExecutionID,
	}
	globalDB.CreateAITaskExecution(exec)
	globalDB.CreateAITaskExecutionEvent(executionID, "execution_completed", output.Status)
	globalDB.CreateAIResult(executionID, output.ResultData, output.Sources, output.Warnings, output.Errors)

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "ai.task.execute",
		Resource: "/api/v1/ai/tasks/" + taskID + "/execute",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"execution_id": executionID,
		"status":       output.Status,
		"result_data":  output.ResultData,
		"sources":      output.Sources,
		"warnings":     output.Warnings,
		"errors":       output.Errors,
	})
}

func handleListExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "task_id required")
		return
	}

	executions, err := globalDB.ListAITaskExecutions(taskID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list executions")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "ai.execution.list",
		Resource: "/api/v1/ai/executions",
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"executions": executions,
		"count":      len(executions),
	})
}

func handleGetExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}

	executionID := r.PathValue("execution_id")
	exec := &AITaskExecution{}
	err := globalDB.QueryRow(`SELECT execution_id, task_id, harness_id, model_provider, model_name,
		prompt_version, workflow_version, input_reference, output_reference, start_time, end_time, status, error, created_at
		FROM ai_executions WHERE execution_id = ?`, executionID).
		Scan(&exec.ExecutionID, &exec.TaskID, &exec.HarnessID, &exec.ModelProvider, &exec.ModelName,
			&exec.PromptVersion, &exec.WorkflowVersion, &exec.InputReference, &exec.OutputReference,
			&exec.StartTime, &exec.EndTime, &exec.Status, &exec.Error, &exec.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "NOT_FOUND", "execution not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get execution")
		return
	}

	task, err := globalDB.GetAITask(exec.TaskID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to verify task access")
		return
	}
	if task == nil || task.ClientID != session.ClientID {
		writeJSONError(w, http.StatusForbidden, "TENANT_ISOLATION_VIOLATION", "not authorized for this execution")
		return
	}

	globalAuditLogger.Log(AuditEvent{
		UserID:   session.UserID,
		ClientID: session.ClientID,
		Action:   "ai.execution.read",
		Resource: "/api/v1/ai/executions/" + executionID,
		Result:   "success",
		SourceIP: r.RemoteAddr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(exec)
}
