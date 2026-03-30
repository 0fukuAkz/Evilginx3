package database

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/tidwall/buntdb"
)

const AuditTable = "audit"

type AuditEntry struct {
	Id        int    `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Username  string `json:"username"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
	IPAddr    string `json:"ip_addr"`
}

func (d *Database) auditInit() {
	d.db.CreateIndex("audit_id", AuditTable+":*", buntdb.IndexJSON("id"))
}

func (d *Database) auditCreate(username string, action string, detail string, ip string) (*AuditEntry, error) {
	id, _ := d.getNextId(AuditTable)

	entry := &AuditEntry{
		Id:        id,
		Timestamp: time.Now().UTC().Unix(),
		Username:  username,
		Action:    action,
		Detail:    detail,
		IPAddr:    ip,
	}

	jf, _ := json.Marshal(entry)

	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(AuditTable, id), string(jf), nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func (d *Database) auditList(limit int) ([]*AuditEntry, error) {
	entries := []*AuditEntry{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		tx.Ascend("audit_id", func(key, val string) bool {
			e := &AuditEntry{}
			if err := json.Unmarshal([]byte(val), e); err == nil {
				entries = append(entries, e)
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort newest first
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp > entries[j].Timestamp
	})

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

func (d *Database) auditClear() error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		var keys []string
		tx.Ascend("audit_id", func(key, val string) bool {
			keys = append(keys, key)
			return true
		})
		for _, key := range keys {
			if _, err := tx.Delete(key); err != nil {
				return fmt.Errorf("failed to delete audit key %s: %v", key, err)
			}
		}
		return nil
	})
}

// Public methods

func (d *Database) CreateAuditEntry(username string, action string, detail string, ip string) (*AuditEntry, error) {
	return d.auditCreate(username, action, detail, ip)
}

func (d *Database) ListAuditEntries(limit int) ([]*AuditEntry, error) {
	return d.auditList(limit)
}

func (d *Database) ClearAuditLog() error {
	return d.auditClear()
}
