package main

import (
	"encoding/json"
	"net/http"
)

// ---------- QRadar Instances ----------

func handleListQRadarInstances(w http.ResponseWriter, r *http.Request) {
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
	if clientID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id required")
		return
	}
	insts, err := ListQRadarInstances(session.UserID, clientID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"instances": insts, "count": len(insts)})
}

func handleCreateQRadarInstance(w http.ResponseWriter, r *http.Request) {
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
		ClientID    string `json:"client_id"`
		InstanceName string `json:"instance_name"`
		Host        string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" || req.InstanceName == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id and instance_name required")
		return
	}
	inst, err := CreateQRadarInstance(session.UserID, req.ClientID, req.InstanceName, req.Host)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(inst)
}

func handleGetQRadarInstance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	inst, err := GetQRadarInstance(r.PathValue("instance_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inst)
}

// ---------- QRadar Domains ----------

func handleListQRadarDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	instanceID := r.URL.Query().Get("instance_id")
	if instanceID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "instance_id required")
		return
	}
	doms, err := ListQRadarDomains(session.UserID, instanceID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"domains": doms, "count": len(doms)})
}

func handleCreateQRadarDomain(w http.ResponseWriter, r *http.Request) {
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
		InstanceID  string `json:"instance_id"`
		DomainName  string `json:"domain_name"`
		DomainType  string `json:"domain_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.InstanceID == "" || req.DomainName == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "instance_id and domain_name required")
		return
	}
	dom, err := CreateQRadarDomain(session.UserID, req.InstanceID, req.DomainName, req.DomainType)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(dom)
}

func handleGetQRadarDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	dom, err := GetQRadarDomain(r.PathValue("domain_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dom)
}

// ---------- QRadar Log Source Types ----------

func handleListQRadarLogSourceTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	domainID := r.URL.Query().Get("domain_id")
	if domainID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "domain_id required")
		return
	}
	types, err := ListQRadarLogSourceTypes(session.UserID, domainID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"log_source_types": types, "count": len(types)})
}

func handleCreateQRadarLogSourceType(w http.ResponseWriter, r *http.Request) {
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
		DomainID string `json:"domain_id"`
		TypeName string `json:"type_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DomainID == "" || req.TypeName == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "domain_id and type_name required")
		return
	}
	t, err := CreateQRadarLogSourceType(session.UserID, req.DomainID, req.TypeName)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(t)
}

func handleGetQRadarLogSourceType(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	t, err := GetQRadarLogSourceType(r.PathValue("log_source_type_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}

// ---------- QRadar Log Sources ----------

func handleListQRadarLogSources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	logSourceTypeID := r.URL.Query().Get("log_source_type_id")
	if logSourceTypeID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "log_source_type_id required")
		return
	}
	srcs, err := ListQRadarLogSources(session.UserID, logSourceTypeID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"log_sources": srcs, "count": len(srcs)})
}

func handleCreateQRadarLogSource(w http.ResponseWriter, r *http.Request) {
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
		LogSourceTypeID string `json:"log_source_type_id"`
		Status          string `json:"status"`
		DataProvenance  string `json:"data_provenance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LogSourceTypeID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "log_source_type_id required")
		return
	}
	ls, err := CreateQRadarLogSource(session.UserID, req.LogSourceTypeID, req.Status, req.DataProvenance)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ls)
}

func handleGetQRadarLogSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	ls, err := GetQRadarLogSource(r.PathValue("log_source_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ls)
}

// ---------- QRadar QIDs ----------

func handleListQRadarQIDs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	logSourceID := r.URL.Query().Get("log_source_id")
	if logSourceID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "log_source_id required")
		return
	}
	qids, err := ListQRadarQIDs(session.UserID, logSourceID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"qradar_qids": qids, "count": len(qids)})
}

func handleCreateQRadarQID(w http.ResponseWriter, r *http.Request) {
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
		LogSourceID    string `json:"log_source_id"`
		EventName      string `json:"event_name"`
		NativeEventID  string `json:"native_event_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.LogSourceID == "" || req.EventName == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "log_source_id and event_name required")
		return
	}
	q, err := CreateQRadarQID(session.UserID, req.LogSourceID, req.EventName, req.NativeEventID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(q)
}

func handleGetQRadarQID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	q, err := GetQRadarQID(r.PathValue("qid"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(q)
}

// ---------- Field Definitions ----------

func handleListQRadarFieldDefinitions(w http.ResponseWriter, r *http.Request) {
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
	domainID := r.URL.Query().Get("domain_id")
	if clientID == "" || domainID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id and domain_id required")
		return
	}
	defs, err := ListQRadarFieldDefinitions(session.UserID, clientID, domainID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"field_definitions": defs, "count": len(defs)})
}

func handleCreateQRadarFieldDefinition(w http.ResponseWriter, r *http.Request) {
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
		ClientID           string `json:"client_id"`
		DomainID           string `json:"domain_id"`
		FieldName          string `json:"field_name"`
		FieldOrigin        string `json:"field_origin"`
		DataType           string `json:"data_type"`
		CEPIdentifier      string `json:"cep_identifier"`
		SupportedEventScope string `json:"supported_event_scope"`
		AQLFieldExpression string `json:"aql_field_expression"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" || req.DomainID == "" || req.FieldName == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id, domain_id and field_name required")
		return
	}
	f, err := CreateQRadarFieldDefinition(session.UserID, req.ClientID, req.DomainID, req.FieldName, req.FieldOrigin, req.DataType, req.CEPIdentifier, req.SupportedEventScope, req.AQLFieldExpression)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(f)
}

func handleGetQRadarFieldDefinition(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	f, err := GetQRadarFieldDefinition(r.PathValue("field_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(f)
}

// ---------- Field Mappings ----------

func handleListQRadarFieldMappings(w http.ResponseWriter, r *http.Request) {
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
	domainID := r.URL.Query().Get("domain_id")
	if clientID == "" || domainID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id and domain_id required")
		return
	}
	maps, err := ListQRadarFieldMappings(session.UserID, clientID, domainID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"field_mappings": maps, "count": len(maps)})
}

func handleCreateQRadarFieldMapping(w http.ResponseWriter, r *http.Request) {
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
		ClientID           string `json:"client_id"`
		DomainID           string `json:"domain_id"`
		RawSourceField     string `json:"raw_source_field"`
		TargetCEPField     string `json:"target_cep_field"`
		SemanticAlias      string `json:"semantic_alias"`
		ApplicableDSM      string `json:"applicable_dsm"`
		ApplicableEvent    string `json:"applicable_event"`
		MappingVersion     string `json:"mapping_version"`
		Origin             string `json:"origin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" || req.DomainID == "" || req.RawSourceField == "" || req.TargetCEPField == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id, domain_id, raw_source_field and target_cep_field required")
		return
	}
	m, err := CreateQRadarFieldMapping(session.UserID, req.ClientID, req.DomainID, req.RawSourceField, req.TargetCEPField, req.SemanticAlias, req.ApplicableDSM, req.ApplicableEvent, req.MappingVersion, req.Origin)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(m)
}

func handleGetQRadarFieldMapping(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	m, err := GetQRadarFieldMapping(r.PathValue("mapping_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}

// ---------- Field Observations ----------

func handleListQRadarFieldObservations(w http.ResponseWriter, r *http.Request) {
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
	domainID := r.URL.Query().Get("domain_id")
	if clientID == "" || domainID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id and domain_id required")
		return
	}
	obs, err := ListQRadarFieldObservations(session.UserID, clientID, domainID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"field_observations": obs, "count": len(obs)})
}

func handleCreateQRadarFieldObservation(w http.ResponseWriter, r *http.Request) {
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
		ClientID               string `json:"client_id"`
		DomainID               string `json:"domain_id"`
		FieldID                string `json:"field_id"`
		FieldPresentInRaw      bool   `json:"field_present_in_raw"`
		QRadarPropertyDisplayed bool  `json:"qradar_property_displayed"`
		ExtractedValuePresent   bool  `json:"extracted_value_present"`
		AQLVerificationStatus  string `json:"aql_verification_status"`
		VerificationTimestamp  string `json:"verification_timestamp"`
		VerifiedBy             string `json:"verified_by"`
		EvidenceReference      string `json:"evidence_reference"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" || req.DomainID == "" || req.FieldID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id, domain_id and field_id required")
		return
	}
	o, err := CreateQRadarFieldObservation(session.UserID, req.ClientID, req.DomainID, req.FieldID, req.FieldPresentInRaw, req.QRadarPropertyDisplayed, req.ExtractedValuePresent, req.AQLVerificationStatus, req.VerificationTimestamp, req.VerifiedBy, req.EvidenceReference)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(o)
}

func handleGetQRadarFieldObservation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	o, err := GetQRadarFieldObservation(r.PathValue("observation_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(o)
}

// ---------- Import Batches ----------

func handleListQRadarImportBatches(w http.ResponseWriter, r *http.Request) {
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
	if clientID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id required")
		return
	}
	batches, err := ListQRadarImportBatches(session.UserID, clientID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"import_batches": batches, "count": len(batches)})
}

func handleCreateQRadarImportBatch(w http.ResponseWriter, r *http.Request) {
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
		ClientID      string `json:"client_id"`
		DomainID      string `json:"domain_id"`
		BatchName     string `json:"batch_name"`
		SourceType    string `json:"source_type"`
		FileHash      string `json:"file_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" || req.DomainID == "" || req.BatchName == "" || req.SourceType == "" || req.FileHash == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id, domain_id, batch_name, source_type and file_hash required")
		return
	}
	b, err := CreateQRadarImportBatch(session.UserID, req.ClientID, req.DomainID, req.BatchName, req.SourceType, req.FileHash)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(b)
}

func handleGetQRadarImportBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	b, err := GetQRadarImportBatch(r.PathValue("batch_id"), session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b)
}

// ---------- Import Rows ----------

func handleListQRadarImportRows(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	batchID := r.URL.Query().Get("batch_id")
	if batchID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "batch_id required")
		return
	}
	rows, err := ListQRadarImportRows(batchID, session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"import_rows": rows, "count": len(rows)})
}

// ---------- Import Field Map ----------

func handleCreateQRadarImportFieldMap(w http.ResponseWriter, r *http.Request) {
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
		BatchID            string `json:"batch_id"`
		RawFieldName       string `json:"raw_field_name"`
		NormalizedFieldName string `json:"normalized_field_name"`
		SuggestedCEPField  string `json:"suggested_cep_field"`
		MappingConfidence  string `json:"mapping_confidence"`
		Evidence           string `json:"evidence"`
		Ambiguous          bool   `json:"ambiguous"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.BatchID == "" || req.RawFieldName == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "batch_id and raw_field_name required")
		return
	}
	if err := CreateQRadarImportFieldMap(session.UserID, req.BatchID, req.RawFieldName, req.NormalizedFieldName, req.SuggestedCEPField, req.MappingConfidence, req.Evidence, req.Ambiguous); err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "created"})
}

func handleListQRadarImportFieldMaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	batchID := r.URL.Query().Get("batch_id")
	if batchID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "batch_id required")
		return
	}
	maps, err := ListQRadarImportFieldMaps(batchID, session.UserID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"field_mappings": maps, "count": len(maps)})
}

// ---------- Publish Batch ----------

func handlePublishQRadarImportBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	batchID := r.PathValue("batch_id")
	b, err := PublishQRadarImportBatch(session.UserID, batchID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b)
}

// ---------- Review ----------

func handleReviewQRadarImportBatch(w http.ResponseWriter, r *http.Request) {
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
		Decision string `json:"decision"`
		Evidence string `json:"evidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "decision required (APPROVED|REJECTED) and evidence required")
		return
	}
	b, err := ReviewQRadarImportBatch(session.UserID, r.PathValue("batch_id"), req.Decision, req.Evidence)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b)
}

// ---------- Mapping approval ----------

func handleApproveQRadarFieldMapping(w http.ResponseWriter, r *http.Request) {
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
		Evidence string `json:"evidence"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	m, err := ApproveQRadarFieldMapping(session.UserID, r.PathValue("mapping_id"), req.Evidence)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}

// ---------- File Import ----------

func handleImportQRadarFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "failed to parse multipart form")
		return
	}
	clientID := r.FormValue("client_id")
	domainID := r.FormValue("domain_id")
	batchName := r.FormValue("batch_name")
	sourceType := r.FormValue("source_type")
	if clientID == "" || domainID == "" || batchName == "" || sourceType == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "client_id, domain_id, batch_name and source_type required")
		return
	}
	if !hasClientGrant(session.UserID, clientID) {
		writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "access denied")
		return
	}
	file, fh, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "file required")
		return
	}
	defer file.Close()
	batch, err := ProcessImportFile(file, fh.Filename, session.UserID, clientID, domainID, batchName, sourceType)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"batch": batch, "status": "created"})
}

// ---------- End ----------

// ---------- Domain bindings (Phase 2A.1) ----------

func handleListDomainBindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	instanceID := r.URL.Query().Get("instance_id")
	if instanceID == "" {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "instance_id required")
		return
	}
	items, err := ListDomainBindings(session.UserID, instanceID)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"domain_bindings": items, "count": len(items)})
}

func handleUpdateDomainBinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "PUT required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	var req DomainBindingUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid binding payload")
		return
	}
	b, err := UpdateDomainBinding(session.UserID, r.PathValue("domain_id"), req)
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b)
}

func handleDomainBindingHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	session := sessionFromContext(r.Context())
	if session == nil {
		writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED", "no session")
		return
	}
	items, err := ListDomainBindingHistory(session.UserID, r.PathValue("domain_id"))
	if err != nil {
		mapHuntError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"history": items, "count": len(items)})
}
