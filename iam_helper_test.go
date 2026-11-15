package ibmcloudsecrets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAddServiceIDToAccessGroup_Request exercises the real HTTP helper (not the mock) and checks
// the request sent to the IAM Access Groups API, including the Bearer authorization header.
func TestAddServiceIDToAccessGroup_Request(t *testing.T) {
	const (
		token   = "test-iam-token"
		iamID   = "iam-ServiceId-1234"
		groupID = "AccessGroupId-abcd"
	)

	var (
		gotMethod, gotPath, gotAuth string
		gotBody                     AddGroupMembersRequest
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed decoding request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMultiStatus)
		_ = json.NewEncoder(w).Encode(AddGroupMembersResponse{
			Members: []AddGroupMembersResponseMembers{{IAMID: iamID, Status: http.StatusOK}},
		})
	}))
	defer server.Close()

	h := &ibmCloudHelper{}
	h.Init(server.URL)
	defer h.Cleanup()

	if err := h.AddServiceIDToAccessGroup(token, iamID, groupID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuth != "Bearer "+token {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer "+token)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want %q", gotMethod, http.MethodPut)
	}
	if wantPath := "/v2/groups/" + groupID + "/members"; gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if len(gotBody.Members) != 1 || gotBody.Members[0]["iam_id"] != iamID || gotBody.Members[0]["type"] != "service" {
		t.Errorf("unexpected request body members: %v", gotBody.Members)
	}
}
