import pathlib

p = pathlib.Path(r'C:\Users\Бауыржан\Desktop\QC_Bots\backend\field_intel.go')
t = p.read_text(encoding='utf-8')

# Fix 1: Line ~563 - remove unused clientID variable declaration
# The line is: "var clientID string" inside GetQRadarFieldDefinition
# We need to remove this line since clientID is not used

# Fix 2: Line ~625 - same issue in GetQRadarFieldObservation

# Fix 3: Lines ~795 and 846 - batchID redeclared
# Fix 4: Line ~950 - sha256.Sum256 returns [32]byte, need hex.EncodeToString(sha256.Sum256(data))
# Fix 5: Lines ~974, 980 - batchID undefined

# Let's fix each issue

# Fix 1: Remove "var clientID string" from GetQRadarFieldDefinition
t = t.replace(
    'var f QRadarFieldDefinition\n\tvar clientID string\n\terr := globalDB.QueryRow(`SELECT f.field_id, f.client_id, f.domain_id, f.field_name, f.field_origin, f.data_type, f.cep_identifier, f.supported_event_scope, f.aql_field_expression, f.created_at\n\t\tFROM qradar_field_definitions f WHERE f.field_id = ?`, fieldID).\n\t\t\tScan(&f.FieldID, &f.ClientID, &f.DomainID, &f.FieldName, &f.FieldOrigin, &f.DataType, &f.CEPIdentifier, &f.SupportedEventScope, &f.AQLFieldExpression, &f.CreatedAt)',
    'var f QRadarFieldDefinition\n\terr := globalDB.QueryRow(`SELECT f.field_id, f.client_id, f.domain_id, f.field_name, f.field_origin, f.data_type, f.cep_identifier, f.supported_event_scope, f.aql_field_expression, f.created_at\n\t\tFROM qradar_field_definitions f WHERE f.field_id = ?`, fieldID).\n\t\t\tScan(&f.FieldID, &f.ClientID, &f.DomainID, &f.FieldName, &f.FieldOrigin, &f.DataType, &f.CEPIdentifier, &f.SupportedEventScope, &f.AQLFieldExpression, &f.CreatedAt)'
)

print('Fix 1 done:', 'var clientID string' not in t[:3000])

p.write_text(t, encoding='utf-8')
print('done')