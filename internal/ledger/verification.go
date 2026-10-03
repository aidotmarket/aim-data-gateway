package ledger

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var ErrConsent = errors.New("consent_refused")

const verificationSchema = `
CREATE TABLE IF NOT EXISTS verification_admissions (
 spec_id TEXT PRIMARY KEY, runner_id TEXT NOT NULL,listing_id TEXT NOT NULL,listing_version_id TEXT NOT NULL,
 manifest_hash TEXT NOT NULL,spec_hash TEXT NOT NULL,nonce TEXT NOT NULL UNIQUE,owner_authorization_id TEXT NOT NULL UNIQUE,
 accepted_at INTEGER NOT NULL,issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,committed_at INTEGER NOT NULL,
 utc_day TEXT NOT NULL,variant TEXT NOT NULL CHECK(variant IN ('probe','scan')),
 state TEXT NOT NULL CHECK(state IN ('accepted','running','reported','refused','interrupted')),
 spec_bytes BLOB NOT NULL,result_bytes BLOB,audit_seq INTEGER,snapshot_bytes BLOB NOT NULL,iid TEXT NOT NULL,delivered INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS verification_daily(listing_id TEXT NOT NULL,utc_day TEXT NOT NULL,accepted_count INTEGER NOT NULL CHECK(accepted_count BETWEEN 0 AND 10),PRIMARY KEY(listing_id,utc_day));
CREATE TABLE IF NOT EXISTS verification_clock(singleton INTEGER PRIMARY KEY CHECK(singleton=1),last_utc INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS verification_local_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,received_at INTEGER NOT NULL,spec_hash TEXT,spec_id TEXT,result TEXT NOT NULL,refusal_code TEXT,authorization_id TEXT,nonce TEXT,spec_bytes BLOB);
`

type Admission struct {
	SpecID, RunnerID, ListingID, VersionID, ManifestHash, SpecHash, Nonce, AuthorizationID, Variant, State, IID string
	Accepted, Issued, Expires, Committed                                                                        int64
	Spec, Snapshot, Result                                                                                      []byte
	AuditSeq                                                                                                    sql.NullInt64
}
type LocalEvent struct {
	ID          int64  `json:"event_id"`
	Time        string `json:"time"`
	SpecHash    string `json:"spec_hash"`
	SpecID      string `json:"spec_id"`
	Result      string `json:"result"`
	RefusalCode string `json:"refusal_code"`
}

// Admit uses BEGIN IMMEDIATE on a dedicated connection: duplicate, replay, clock
// high-water, quota and authorization consumption are one FULL durable commit.
func (l *Ledger) Admit(ctx context.Context, a Admission, at time.Time) (bool, error) {
	c, e := l.DB.Conn(ctx)
	if e != nil {
		return false, e
	}
	defer c.Close()
	if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		return false, e
	}
	defer c.ExecContext(context.Background(), "ROLLBACK")
	var hash string
	e = c.QueryRowContext(ctx, "SELECT spec_hash FROM verification_admissions WHERE spec_id=?", a.SpecID).Scan(&hash)
	if e == nil {
		if hash != a.SpecHash {
			return false, ErrConsent
		}
		return false, nil
	}
	if e != sql.ErrNoRows {
		return false, e
	}
	var last int64
	e = c.QueryRowContext(ctx, "SELECT last_utc FROM verification_clock WHERE singleton=1").Scan(&last)
	if e != nil && e != sql.ErrNoRows {
		return false, e
	}
	if at.Unix() < last-300 {
		return false, ErrConsent
	}
	day := at.UTC().Format("2006-01-02")
	if _, e = c.ExecContext(ctx, "INSERT OR IGNORE INTO verification_daily VALUES(?,?,0)", a.ListingID, day); e != nil {
		return false, e
	}
	r, e := c.ExecContext(ctx, "UPDATE verification_daily SET accepted_count=accepted_count+1 WHERE listing_id=? AND utc_day=? AND accepted_count<10", a.ListingID, day)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	if e != nil {
		return false, e
	}
	if n != 1 {
		return false, ErrConsent
	}
	_, e = c.ExecContext(ctx, `INSERT INTO verification_admissions(spec_id,runner_id,listing_id,listing_version_id,manifest_hash,spec_hash,nonce,owner_authorization_id,accepted_at,issued_at,expires_at,committed_at,utc_day,variant,state,spec_bytes,snapshot_bytes,iid) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'accepted',?,?,?)`, a.SpecID, a.RunnerID, a.ListingID, a.VersionID, a.ManifestHash, a.SpecHash, a.Nonce, a.AuthorizationID, a.Accepted, a.Issued, a.Expires, at.Unix(), day, a.Variant, a.Spec, a.Snapshot, a.IID)
	if e != nil {
		return false, ErrConsent
	}
	if _, e = c.ExecContext(ctx, "INSERT INTO verification_clock VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET last_utc=max(last_utc,excluded.last_utc)", at.Unix()); e != nil {
		return false, e
	}
	if _, e = c.ExecContext(ctx, `INSERT INTO verification_local_events(received_at,spec_hash,spec_id,result,refusal_code,authorization_id,nonce,spec_bytes) VALUES(?,?,?,'accepted','',?,?,?)`, at.Unix(), a.SpecHash, a.SpecID, a.AuthorizationID, a.Nonce, a.Spec); e != nil {
		return false, e
	}
	_, e = c.ExecContext(ctx, "COMMIT")
	return e == nil, e
}
func (l *Ledger) VerificationEvent(ctx context.Context, a Admission, result, code string, at time.Time) error {
	_, e := l.DB.ExecContext(ctx, `INSERT INTO verification_local_events(received_at,spec_hash,spec_id,result,refusal_code,authorization_id,nonce,spec_bytes) VALUES(?,?,?,?,?,?,?,?)`, at.Unix(), a.SpecHash, a.SpecID, result, code, a.AuthorizationID, a.Nonce, a.Spec)
	return e
}
func (l *Ledger) VerificationEvents(ctx context.Context, after int64) ([]LocalEvent, error) {
	rows, e := l.DB.QueryContext(ctx, "SELECT event_id,received_at,coalesce(spec_hash,''),coalesce(spec_id,''),result,coalesce(refusal_code,'') FROM verification_local_events WHERE event_id>? ORDER BY event_id", after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []LocalEvent{}
	for rows.Next() {
		var v LocalEvent
		var at int64
		if e = rows.Scan(&v.ID, &at, &v.SpecHash, &v.SpecID, &v.Result, &v.RefusalCode); e != nil {
			return nil, e
		}
		v.Time = time.Unix(at, 0).UTC().Format(time.RFC3339)
		out = append(out, v)
	}
	return out, rows.Err()
}

const admissionSelect = `SELECT spec_id,runner_id,listing_id,listing_version_id,manifest_hash,spec_hash,nonce,owner_authorization_id,variant,state,iid,accepted_at,issued_at,expires_at,committed_at,spec_bytes,snapshot_bytes,result_bytes,audit_seq FROM verification_admissions`

func scanAdmission(row interface{ Scan(...any) error }) (a Admission, e error) {
	e = row.Scan(&a.SpecID, &a.RunnerID, &a.ListingID, &a.VersionID, &a.ManifestHash, &a.SpecHash, &a.Nonce, &a.AuthorizationID, &a.Variant, &a.State, &a.IID, &a.Accepted, &a.Issued, &a.Expires, &a.Committed, &a.Spec, &a.Snapshot, &a.Result, &a.AuditSeq)
	return
}
func (l *Ledger) Verification(ctx context.Context, id string) (Admission, error) {
	return scanAdmission(l.DB.QueryRowContext(ctx, admissionSelect+" WHERE spec_id=?", id))
}
func (l *Ledger) Verifications(ctx context.Context) ([]Admission, error) {
	rows, e := l.DB.QueryContext(ctx, admissionSelect+" ORDER BY committed_at,spec_id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Admission{}
	for rows.Next() {
		a, e := scanAdmission(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (l *Ledger) ClaimVerification(ctx context.Context, id string) (bool, error) {
	r, e := l.DB.ExecContext(ctx, "UPDATE verification_admissions SET state='running' WHERE spec_id=? AND state='accepted'", id)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
func (l *Ledger) SaveVerification(ctx context.Context, id, state string, result []byte) error {
	_, e := l.DB.ExecContext(ctx, "UPDATE verification_admissions SET state=?,result_bytes=? WHERE spec_id=? AND result_bytes IS NULL", state, result, id)
	return e
}
func (l *Ledger) AuditVerification(ctx context.Context, id string, seq uint64) error {
	_, e := l.DB.ExecContext(ctx, "UPDATE verification_admissions SET audit_seq=? WHERE spec_id=? AND (audit_seq IS NULL OR audit_seq=?)", seq, id, seq)
	return e
}
func (l *Ledger) ReconcileVerification(ctx context.Context, seq uint64) error {
	_, e := l.DB.ExecContext(ctx, "UPDATE verification_admissions SET delivered=(audit_seq<=?) WHERE audit_seq IS NOT NULL", seq)
	return e
}
func (l *Ledger) InterruptVerifications(ctx context.Context) error {
	_, e := l.DB.ExecContext(ctx, "UPDATE verification_admissions SET state='interrupted' WHERE state IN ('accepted','running')")
	return e
}
func (l *Ledger) PruneVerification(ctx context.Context, at time.Time) error {
	cutoff := at.Add(-30 * 24 * time.Hour).Unix()
	return tx(ctx, l.DB, func(t *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM verification_local_events WHERE received_at<? AND NOT EXISTS(SELECT 1 FROM verification_admissions a WHERE a.spec_id=verification_local_events.spec_id AND (a.delivered=0 OR a.state IN ('accepted','running')))`,
			`DELETE FROM verification_admissions WHERE committed_at<? AND state IN ('reported','refused','interrupted') AND delivered=1`,
			`DELETE FROM verification_daily WHERE utc_day<date(?,'unixepoch') AND NOT EXISTS(SELECT 1 FROM verification_admissions a WHERE a.listing_id=verification_daily.listing_id AND a.utc_day=verification_daily.utc_day)`} {
			if _, e := t.ExecContext(ctx, q, cutoff); e != nil {
				return e
			}
		}
		return nil
	})
}

// OpenVerificationPreview opens an existing ledger read-only and performs no
// migrations, crash recovery, pragmas, or checkpoint writes.
func OpenVerificationPreview(path string) (*Ledger, error) {
	db, e := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	if e = db.Ping(); e != nil {
		db.Close()
		return nil, e
	}
	return &Ledger{DB: db}, nil
}
