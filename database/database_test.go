package database

import (
	"testing"
)

func TestDatabase_Sessions(t *testing.T) {
	// Use in-memory database
	db, err := NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory database: %v", err)
	}

	// 1. Create Session
	sid := "session_123"
	phishlet := "test_phish"
	landing := "/login"
	ua := "Go-Test-Agent"
	ip := "127.0.0.1"

	err = db.CreateSession(sid, phishlet, landing, ua, ip)
	if err != nil {
		t.Errorf("CreateSession failed: %v", err)
	}

	// 2. List and Verify
	sessions, err := db.ListSessions()
	if err != nil {
		t.Errorf("ListSessions failed: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session, got %d", len(sessions))
	}
	s := sessions[0]
	if s.SessionId != sid || s.Phishlet != phishlet {
		t.Errorf("Session data mismatch: %+v", s)
	}

	// 3. Update Username
	username := "hacker@example.com"
	err = db.SetSessionUsername(sid, username)
	if err != nil {
		t.Errorf("SetSessionUsername failed: %v", err)
	}

	// Verify Update
	sessions, _ = db.ListSessions()
	if sessions[0].Username != username {
		t.Errorf("Username not updated. Expected %s, got %s", username, sessions[0].Username)
	}

	// 4. Update Custom Field
	err = db.SetSessionCustom(sid, "test_key", "test_val")
	if err != nil {
		t.Errorf("SetSessionCustom failed: %v", err)
	}

	// 5. Delete Session
	err = db.DeleteSession(sid)
	if err != nil {
		t.Errorf("DeleteSession failed: %v", err)
	}

	sessions, _ = db.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions after delete, got %d", len(sessions))
	}
}

func TestDatabase_Reporting(t *testing.T) {
	db, _ := NewDatabase(":memory:")
	sid := "sess_report"
	db.CreateSession(sid, "test", "/", "ua", "127.0.0.1")

	// Initially no username/pass, so not unreported (needs creds to be worth reporting?)
	// specific logic in GetUnreportedSessions:
	// if !s.Reported && s.Username != "" && s.Password != ""

	unreported, _ := db.GetUnreportedSessions()
	if len(unreported) != 0 {
		t.Errorf("Should be 0 unreported (no creds)")
	}

	db.SetSessionUsername(sid, "user")
	db.SetSessionPassword(sid, "pass")

	unreported, _ = db.GetUnreportedSessions()
	if len(unreported) != 1 {
		t.Errorf("Should be 1 unreported")
	}

	db.MarkSessionReported(sid)

	unreported, _ = db.GetUnreportedSessions()
	if len(unreported) != 0 {
		t.Errorf("Should be 0 unreported after mark")
	}
}

func TestDatabase_ActiveSessions(t *testing.T) {
	db, _ := NewDatabase(":memory:")
	db.CreateSession("active", "test", "/", "ua", "1.1.1.1")

	active, _ := db.GetActiveSessions()
	if len(active) != 1 {
		t.Errorf("Should be 1 active session")
	}
	// Cannot easily test "old" session without sleeping 1 hour or mocking time.
	// But this covers the function call.
}
