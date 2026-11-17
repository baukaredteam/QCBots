package main

import "testing"

func TestMappingCandidatesDeterministic(t *testing.T) {
	observed := map[string]map[string]int{
		"EventID":  {"integer": 3},
		"TaskName": {"string": 3},
		"cs-method": {"string": 2},
		"sc-status": {"integer": 2},
	}
	got := buildCandidates(observed)
	want := map[string]string{
		"EventID": "event_id", "TaskName": "task_name",
		"cs-method": "http_method", "sc-status": "http_code",
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d candidates, got %d: %+v", len(want), len(got), got)
	}
	for _, c := range got {
		if want[c.RawField] != c.CEP {
			t.Fatalf("unexpected candidate %+v", c)
		}
		if c.Ambiguous {
			t.Fatalf("unambiguous field flagged ambiguous: %+v", c)
		}
	}
}

func TestMappingCollisionIsAmbiguous(t *testing.T) {
	observed := map[string]map[string]int{
		"EventID":   {"integer": 2},
		"EventCode": {"integer": 2},
	}
	got := buildCandidates(observed)
	if len(got) != 2 {
		t.Fatalf("expected two candidates, got %+v", got)
	}
	for _, c := range got {
		if !c.Ambiguous {
			t.Fatalf("two raw fields claiming event_id must be ambiguous: %+v", c)
		}
		if c.Confidence != "low" {
			t.Fatalf("ambiguous candidate must be low confidence: %+v", c)
		}
	}
}

func TestMappingTypeMismatchProducesNoCandidate(t *testing.T) {
	// sc-status is an integer CEP field, but the samples look like free text.
	observed := map[string]map[string]int{"sc-status": {"string": 5}}
	if got := buildCandidates(observed); len(got) != 0 {
		t.Fatalf("type mismatch must not produce a candidate: %+v", got)
	}
}

func TestMappingUnknownFieldIgnored(t *testing.T) {
	observed := map[string]map[string]int{"SomeVendorBlob": {"string": 4}}
	if got := buildCandidates(observed); len(got) != 0 {
		t.Fatalf("unknown field must not be mapped by name similarity: %+v", got)
	}
}

func TestRedactionKinds(t *testing.T) {
	fields := map[string]string{
		"email":       "analyst@example.org",
		"src":         "192.168.10.4",
		"Password":    "Hunter2!",
		"url":         "https://x.example.org/path?token=abc123&user=jdoe",
		"CommandLine": "powershell -enc AAAA",
		"EventID":     "4624",
	}
	out, st := redactPairs(fields)
	if out["EventID"] != "4624" {
		t.Fatalf("non-sensitive value must survive: %v", out["EventID"])
	}
	if st.Values == 0 {
		t.Fatal("expected redaction counters to move")
	}
	for _, v := range out {
		if v == "analyst@example.org" || v == "192.168.10.4" || v == "Hunter2!" || v == "powershell -enc AAAA" {
			t.Fatalf("value not redacted: %q", v)
		}
	}
}

func TestParseWindowsTaskContentXML(t *testing.T) {
	r := parseWindows([]byte(`host EventID=4698 TaskContent=<EventData><Data Name="TaskName">\Microsoft\Updater</Data></EventData> SourceName=TaskScheduler`))
	if len(r.Rows) != 1 || r.Rows[0].Fields == nil {
		t.Fatalf("expected one parsed row, got %+v", r)
	}
	if r.Rows[0].Fields["TaskContent.TaskName"] != `\Microsoft\Updater` {
		t.Fatalf("TaskContent not extracted: %+v", r.Rows[0].Fields)
	}
	if r.Rows[0].Types["EventID"] != "integer" {
		t.Fatalf("EventID type evidence missing: %+v", r.Rows[0].Types)
	}
}

func TestParseGenericAmbiguous(t *testing.T) {
	r := parseGeneric([]byte("this is not key value data at all"))
	if len(r.Rows) != 1 || r.Rows[0].Error == "" {
		t.Fatalf("expected a rejection, got %+v", r)
	}
}
