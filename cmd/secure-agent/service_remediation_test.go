package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServiceCommandsSendReviewedIdentityAndBoundedRequests(t *testing.T) {
	var seen []map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		input := map[string]string{}
		if r.Method == "GET" {
			if len(body) != 0 || r.URL.Query().Get("label") != "model" {
				t.Error("invalid receipt request")
			}
		} else if json.Unmarshal(body, &input) != nil {
			t.Error("invalid mutation body")
		}
		seen = append(seen, input)
		w.Write([]byte(`{"state":"fixture"}`))
	}))
	defer server.Close()
	client := server.Client()
	client.Transport = localServiceTestTransport{base: server.URL, next: client.Transport}
	for _, args := range [][]string{{"remediate", "--service-file", "/model.plist"}, {"remediate", "--confirm", "--preview-id", "review", "--preview-hash", "bound"}, {"rollback", "--label", "model"}, {"receipt", "--label", "model"}} {
		if err := runServiceRemediation(client, args, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	if seen[0]["action"] != "preview" || seen[1]["action"] != "apply" || seen[1]["id"] != "review" || seen[1]["preview_hash"] != "bound" || len(seen[1]) != 3 {
		t.Fatalf("unexpected identity: %v", seen)
	}
	for _, args := range [][]string{nil, {"unknown"}, {"remediate", "--preview-id", "id", "--preview-hash", "hash"}, {"remediate", "--confirm", "--service-file", "/model.plist"}, {"rollback", "--confirm", "--label", "model"}, {"receipt", "--label", "model", "--label", "another"}} {
		if err := runServiceRemediation(client, args, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe args admitted: %v", args)
		}
	}
	if len(seen) != 4 {
		t.Fatal("invalid arguments reached daemon")
	}
}
