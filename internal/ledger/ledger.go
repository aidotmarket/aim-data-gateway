package ledger

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aidotmarket/aim-data-gateway/internal/config"
	"github.com/aidotmarket/aim-data-gateway/internal/inventory"
	"github.com/aidotmarket/aim-data-gateway/internal/wire"
	_ "modernc.org/sqlite"
)

var ErrFragmented = errors.New("coverage_fragmented")
var ErrExhausted = errors.New("coverage_exhausted")
var ErrClosed = errors.New("permission_closed")

const window = int64(inventory.BlockSize)

type Ledger struct {
	DB  *sql.DB
	Key ed25519.PrivateKey
	KID string
}
type File struct {
	ID, Source, RelativePath, SHA256, DisplayName, Root string
	Size                                                int64
	BlockHashes                                         [][32]byte
	Changed                                             bool
}
type Offer struct {
	FileID, SHA256, ListingVersionID, IID, State, KeyClass string
	ApprovedAt                                             sql.NullString
}
type Permission struct {
	wire.Permission
	State string
}
type Request struct {
	ID         int64
	Start, End int64
}

const schema = `
CREATE TABLE IF NOT EXISTS offers(fid TEXT, sha256 TEXT, lvid TEXT, iid TEXT, state TEXT, approved_locally_at TEXT, key_class TEXT, PRIMARY KEY(fid,sha256,lvid));
CREATE TABLE IF NOT EXISTS seen_instructions(iid TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS files(fid TEXT PRIMARY KEY, source TEXT, relative_path TEXT, size INTEGER, mtime TEXT, sha256 TEXT, block_size INTEGER, block_hashes BLOB, display_name TEXT, root TEXT, changed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS permissions(jti TEXT PRIMARY KEY, oid TEXT, fid TEXT, sha256 TEXT, sd INTEGER, td INTEGER, ro INTEGER, state TEXT, bound_at TEXT, closed_at TEXT);
CREATE TABLE IF NOT EXISTS serves(oid TEXT, fid TEXT, start INTEGER, end INTEGER, count INTEGER, PRIMARY KEY(oid,fid,start));
CREATE TABLE IF NOT EXISTS transmitted(oid TEXT, fid TEXT, start INTEGER, end INTEGER, PRIMARY KEY(oid,fid,start));
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, jti TEXT, start INTEGER, end INTEGER, written_through INTEGER, open INTEGER, isolated INTEGER);
CREATE TABLE IF NOT EXISTS revocations(jti TEXT PRIMARY KEY, received_at TEXT);
CREATE TABLE IF NOT EXISTS receipts_outbox(seq INTEGER PRIMARY KEY, body TEXT, sent_at TEXT);
CREATE INDEX IF NOT EXISTS requests_open ON requests(jti,open);`

func Open(path string, key ed25519.PrivateKey, kid string) (*Ledger, error) {
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000", schema} {
		if _, e = db.Exec(q); e != nil {
			db.Close()
			return nil, e
		}
	}
	l := &Ledger{DB: db, Key: key, KID: kid}
	if e = l.Recover(context.Background()); e != nil {
		db.Close()
		return nil, e
	}
	return l, nil
}
func (l *Ledger) Close() error { return l.DB.Close() }
func tx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	t, e := db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer t.Rollback()
	if e = fn(t); e != nil {
		return e
	}
	return t.Commit()
}
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (l *Ledger) Seen(ctx context.Context, iid string) (bool, error) {
	r, e := l.DB.ExecContext(ctx, "INSERT OR IGNORE INTO seen_instructions(iid) VALUES(?)", iid)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 0, e
}
func (l *Ledger) PutFile(ctx context.Context, r inventory.Record) error {
	b, e := json.Marshal(r.BlockHashes)
	if e != nil {
		return e
	}
	_, e = l.DB.ExecContext(ctx, `INSERT INTO files(fid,source,relative_path,size,mtime,sha256,block_size,block_hashes,display_name,root,changed) VALUES(?,?,?,?,?,?,?,?,?,?,0)
	 ON CONFLICT(fid) DO UPDATE SET source=excluded.source,relative_path=excluded.relative_path,size=excluded.size,mtime=excluded.mtime,sha256=excluded.sha256,block_size=excluded.block_size,block_hashes=excluded.block_hashes,display_name=excluded.display_name,root=excluded.root,changed=0`, r.Phase1.FileID, r.Source, r.RelativePath, r.Phase1.SizeBytes, r.Mtime.Format(time.RFC3339Nano), inventory.SHAHex(r), inventory.BlockSize, b, r.Phase1.DisplayName, r.Root)
	return e
}
func (l *Ledger) File(ctx context.Context, fid string) (File, error) {
	var f File
	var b []byte
	var changed int
	e := l.DB.QueryRowContext(ctx, `SELECT fid,source,relative_path,size,sha256,block_hashes,display_name,root,changed FROM files WHERE fid=?`, fid).Scan(&f.ID, &f.Source, &f.RelativePath, &f.Size, &f.SHA256, &b, &f.DisplayName, &f.Root, &changed)
	if e != nil {
		return f, e
	}
	f.Changed = changed != 0
	e = json.Unmarshal(b, &f.BlockHashes)
	return f, e
}
func (l *Ledger) MarkChanged(ctx context.Context, fid string) error {
	_, e := l.DB.ExecContext(ctx, "UPDATE files SET changed=1 WHERE fid=?", fid)
	return e
}
func (f File) Path() string      { return filepath.Join(f.Root, filepath.FromSlash(f.RelativePath)) }
func (f File) ValidBlocks() bool { return int64(len(f.BlockHashes)) == (f.Size+window-1)/window }
func (f File) Hash(i int) [32]byte {
	if i >= 0 && i < len(f.BlockHashes) {
		return f.BlockHashes[i]
	}
	return [32]byte{}
}
func (f File) HashHex() string {
	if len(f.BlockHashes) == 0 {
		return ""
	}
	return hex.EncodeToString(f.BlockHashes[0][:])
}

func (l *Ledger) PutOffer(ctx context.Context, o Offer) error {
	_, e := l.DB.ExecContext(ctx, `INSERT INTO offers(fid,sha256,lvid,iid,state,approved_locally_at,key_class) VALUES(?,?,?,?,?,?,?) ON CONFLICT(fid,sha256,lvid) DO UPDATE SET iid=excluded.iid,state=excluded.state,key_class=excluded.key_class`, o.FileID, o.SHA256, o.ListingVersionID, o.IID, o.State, o.ApprovedAt, o.KeyClass)
	return e
}
func (l *Ledger) Offer(ctx context.Context, fid, sha, lvid string) (Offer, error) {
	var o Offer
	e := l.DB.QueryRowContext(ctx, `SELECT fid,sha256,lvid,iid,state,approved_locally_at,key_class FROM offers WHERE fid=? AND sha256=? AND lvid=?`, fid, sha, lvid).Scan(&o.FileID, &o.SHA256, &o.ListingVersionID, &o.IID, &o.State, &o.ApprovedAt, &o.KeyClass)
	return o, e
}
func (l *Ledger) Approve(ctx context.Context, fid, sha, lvid string) error {
	_, e := l.DB.ExecContext(ctx, `UPDATE offers SET approved_locally_at=? WHERE fid=? AND sha256=? AND lvid=?`, now(), fid, sha, lvid)
	return e
}

func (l *Ledger) Issue(ctx context.Context, p wire.Permission) error {
	_, e := l.DB.ExecContext(ctx, `INSERT OR IGNORE INTO permissions(jti,oid,fid,sha256,sd,td,ro,state) VALUES(?,?,?,?,?,?,?,'issued')`, p.JTI, p.OrderID, p.FileID, p.SHA256, p.StartDeadline, p.TransferDeadline, p.ResumeOffset)
	return e
}
func (l *Ledger) Permission(ctx context.Context, jti string) (Permission, error) {
	var p Permission
	e := l.DB.QueryRowContext(ctx, `SELECT oid,fid,sha256,sd,td,ro,state FROM permissions WHERE jti=?`, jti).Scan(&p.OrderID, &p.FileID, &p.SHA256, &p.StartDeadline, &p.TransferDeadline, &p.ResumeOffset, &p.State)
	p.JTI = jti
	return p, e
}
func (l *Ledger) Bind(ctx context.Context, p wire.Permission) error {
	return tx(ctx, l.DB, func(t *sql.Tx) error {
		var q Permission
		e := t.QueryRowContext(ctx, `SELECT oid,fid,sha256,sd,td,ro,state FROM permissions WHERE jti=?`, p.JTI).Scan(&q.OrderID, &q.FileID, &q.SHA256, &q.StartDeadline, &q.TransferDeadline, &q.ResumeOffset, &q.State)
		if e == sql.ErrNoRows {
			_, e = t.ExecContext(ctx, `INSERT INTO permissions(jti,oid,fid,sha256,sd,td,ro,state,bound_at) VALUES(?,?,?,?,?,?,?,'bound',?)`, p.JTI, p.OrderID, p.FileID, p.SHA256, p.StartDeadline, p.TransferDeadline, p.ResumeOffset, now())
			return e
		}
		if e != nil {
			return e
		}
		if q.OrderID != p.OrderID || q.FileID != p.FileID || q.SHA256 != p.SHA256 || q.StartDeadline != p.StartDeadline || q.TransferDeadline != p.TransferDeadline || q.ResumeOffset != p.ResumeOffset || q.State == "closed" || q.State == "revoked" {
			return ErrClosed
		}
		if q.State == "issued" {
			_, e = t.ExecContext(ctx, `UPDATE permissions SET state='bound',bound_at=? WHERE jti=?`, now(), p.JTI)
		}
		return e
	})
}
func (l *Ledger) CloseExpired(ctx context.Context, at int64) error {
	_, e := l.DB.ExecContext(ctx, `UPDATE permissions SET state='closed',closed_at=? WHERE state IN ('issued','bound') AND td<=?`, now(), at)
	return e
}
func (l *Ledger) Revoke(ctx context.Context, jti string) (wire.RevokeAck, error) {
	a := wire.RevokeAck{Op: "revoke_ack", JTI: jti, StateBefore: "unknown"}
	e := tx(ctx, l.DB, func(t *sql.Tx) error {
		var state string
		var td int64
		e := t.QueryRowContext(ctx, `SELECT state,td FROM permissions WHERE jti=?`, jti).Scan(&state, &td)
		if e != nil && e != sql.ErrNoRows {
			return e
		}
		if e == nil {
			a.StateBefore = "active"
			if state == "closed" || state == "revoked" {
				a.StateBefore = "closed"
			} else if td <= time.Now().Unix() {
				a.StateBefore = "expired"
			}
			_, e = t.ExecContext(ctx, `UPDATE permissions SET state='revoked' WHERE jti=?`, jti)
			if e != nil {
				return e
			}
		}
		_, e = t.ExecContext(ctx, `INSERT OR IGNORE INTO revocations(jti,received_at) VALUES(?,?)`, jti, now())
		return e
	})
	return a, e
}

type segment struct {
	a, b int64
	c    int
}

func segments(ctx context.Context, t *sql.Tx, table, oid, fid string) ([]segment, error) {
	rows, e := t.QueryContext(ctx, "SELECT start,end,"+map[string]string{"serves": "count", "transmitted": "1"}[table]+" FROM "+table+" WHERE oid=? AND fid=? ORDER BY start", oid, fid)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var s []segment
	for rows.Next() {
		var x segment
		if e = rows.Scan(&x.a, &x.b, &x.c); e != nil {
			return nil, e
		}
		s = append(s, x)
	}
	return s, rows.Err()
}
func rewrite(ctx context.Context, t *sql.Tx, table, oid, fid string, s []segment) error {
	if _, e := t.ExecContext(ctx, "DELETE FROM "+table+" WHERE oid=? AND fid=?", oid, fid); e != nil {
		return e
	}
	for _, x := range s {
		if x.c == 0 {
			continue
		}
		q := "INSERT INTO " + table + "(oid,fid,start,end"
		if table == "serves" {
			q += ",count) VALUES(?,?,?,?,?)"
			if _, e := t.ExecContext(ctx, q, oid, fid, x.a, x.b, x.c); e != nil {
				return e
			}
		} else {
			q += ") VALUES(?,?,?,?)"
			if _, e := t.ExecContext(ctx, q, oid, fid, x.a, x.b); e != nil {
				return e
			}
		}
	}
	return nil
}
func transform(s []segment, a, b int64, delta int) []segment {
	if a > b {
		return s
	}
	points := []int64{a, b + 1}
	for _, x := range s {
		points = append(points, x.a, x.b+1)
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	out := []segment{}
	for i := 0; i+1 < len(points); i++ {
		lo, hi := points[i], points[i+1]-1
		if lo > hi {
			continue
		}
		c := 0
		for _, x := range s {
			if x.a <= lo && lo <= x.b {
				c = x.c
				break
			}
		}
		if a <= lo && lo <= b {
			c += delta
		}
		if c <= 0 {
			continue
		}
		if len(out) > 0 && out[len(out)-1].b+1 == lo && out[len(out)-1].c == c {
			out[len(out)-1].b = hi
		} else {
			out = append(out, segment{lo, hi, c})
		}
	}
	return out
}
func covered(s []segment, a, b int64) bool {
	for _, x := range s {
		if x.a <= a && x.b >= b {
			return true
		}
	}
	return false
}
func firstUntransmitted(s []segment, size int64) int64 {
	next := int64(0)
	for _, x := range s {
		if x.a > next {
			break
		}
		if x.b >= next {
			next = x.b + 1
		}
	}
	return min(next, size)
}
func countBytes(s []segment) int64 {
	var n int64
	for _, x := range s {
		n += x.b - x.a + 1
	}
	return n
}
func normalize(s []segment) []segment {
	out := make([]segment, 0, len(s))
	for _, x := range s {
		if len(out) > 0 && x.a <= out[len(out)-1].b+1 && x.c == out[len(out)-1].c {
			out[len(out)-1].b = max(out[len(out)-1].b, x.b)
		} else {
			out = append(out, x)
		}
	}
	return out
}

func (l *Ledger) Reserve(ctx context.Context, p wire.Permission, start, end int64) (Request, error) {
	var out Request
	e := tx(ctx, l.DB, func(t *sql.Tx) error {
		var state, oid, fid, sha string
		var sd, td, ro int64
		err := t.QueryRowContext(ctx, `SELECT oid,fid,sha256,sd,td,ro,state FROM permissions WHERE jti=?`, p.JTI).Scan(&oid, &fid, &sha, &sd, &td, &ro, &state)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil && (oid != p.OrderID || fid != p.FileID || sha != p.SHA256 || sd != p.StartDeadline || td != p.TransferDeadline || ro != p.ResumeOffset || (state != "bound" && state != "issued")) {
			return ErrClosed
		}
		if time.Now().Unix() >= p.TransferDeadline || (state != "bound" && time.Now().Unix() >= p.StartDeadline) {
			return ErrClosed
		}
		var revoked int
		if qerr := t.QueryRowContext(ctx, `SELECT count(*) FROM revocations WHERE jti=?`, p.JTI).Scan(&revoked); qerr != nil {
			return qerr
		}
		if revoked != 0 {
			return ErrClosed
		}
		ss, e := segments(ctx, t, "serves", p.OrderID, p.FileID)
		if e != nil {
			return e
		}
		tr, e := segments(ctx, t, "transmitted", p.OrderID, p.FileID)
		if e != nil {
			return e
		}
		if start < 0 || end < start {
			return errors.New("invalid range")
		}
		// A request writes one contiguous run. Stop before the first byte already at two serves.
		for _, x := range ss {
			if x.c == 2 && x.a <= end && x.b >= start {
				if x.a <= start {
					return ErrExhausted
				}
				end = x.a - 1
				break
			}
		}
		isolate := start > 0 && !covered(tr, start-1, start-1)
		if isolate {
			var open int
			e = t.QueryRowContext(ctx, `SELECT count(*) FROM requests r JOIN permissions p ON p.jti=r.jti WHERE p.oid=? AND p.fid=? AND r.open=1 AND r.isolated=1`, p.OrderID, p.FileID).Scan(&open)
			if e != nil {
				return e
			}
			if len(tr)+open+1 > 1024 {
				return ErrFragmented
			}
		}
		if state != "bound" {
			var offerState, keyClass string
			e = t.QueryRowContext(ctx, `SELECT state,key_class FROM offers WHERE fid=? AND sha256=? AND lvid=?`, p.FileID, p.SHA256, p.ListingVersionID).Scan(&offerState, &keyClass)
			if e != nil || offerState != "offered" || keyClass != "listing" {
				return ErrClosed
			}
			if err == sql.ErrNoRows {
				_, e = t.ExecContext(ctx, `INSERT INTO permissions(jti,oid,fid,sha256,sd,td,ro,state,bound_at) VALUES(?,?,?,?,?,?,?,'bound',?)`, p.JTI, p.OrderID, p.FileID, p.SHA256, p.StartDeadline, p.TransferDeadline, p.ResumeOffset, now())
			} else {
				_, e = t.ExecContext(ctx, `UPDATE permissions SET state='bound',bound_at=? WHERE jti=?`, now(), p.JTI)
			}
			if e != nil {
				return e
			}
		}
		ss = transform(ss, start, end, 1)
		if e = rewrite(ctx, t, "serves", p.OrderID, p.FileID, ss); e != nil {
			return e
		}
		r, e := t.ExecContext(ctx, `INSERT INTO requests(jti,start,end,written_through,open,isolated) VALUES(?,?,?, ?,1,?)`, p.JTI, start, end, start-1, isolate)
		if e != nil {
			return e
		}
		out.ID, e = r.LastInsertId()
		out.Start = start
		out.End = end
		return e
	})
	return out, e
}

// FinishEmpty closes an empty file without creating a fictitious byte range.
func (l *Ledger) FinishEmpty(ctx context.Context, p wire.Permission) error {
	return tx(ctx, l.DB, func(t *sql.Tx) error {
		var size int64
		var sha string
		if e := t.QueryRowContext(ctx, `SELECT size,sha256 FROM files WHERE fid=?`, p.FileID).Scan(&size, &sha); e != nil {
			return e
		}
		if size != 0 || sha != p.SHA256 {
			return ErrClosed
		}
		var revoked int
		if e := t.QueryRowContext(ctx, `SELECT count(*) FROM revocations WHERE jti=?`, p.JTI).Scan(&revoked); e != nil {
			return e
		}
		if revoked != 0 || time.Now().Unix() >= p.StartDeadline || time.Now().Unix() >= p.TransferDeadline {
			return ErrClosed
		}
		var state string
		e := t.QueryRowContext(ctx, `SELECT state FROM permissions WHERE jti=? AND oid=? AND fid=? AND sha256=?`, p.JTI, p.OrderID, p.FileID, p.SHA256).Scan(&state)
		if e != nil && e != sql.ErrNoRows {
			return e
		}
		missing := e == sql.ErrNoRows
		if !missing && state != "issued" && state != "bound" {
			return ErrClosed
		}
		if state != "bound" {
			var offerState, keyClass string
			if e = t.QueryRowContext(ctx, `SELECT state,key_class FROM offers WHERE fid=? AND sha256=? AND lvid=?`, p.FileID, p.SHA256, p.ListingVersionID).Scan(&offerState, &keyClass); e != nil || offerState != "offered" || keyClass != "listing" {
				return ErrClosed
			}
		}
		if missing {
			_, e = t.ExecContext(ctx, `INSERT INTO permissions(jti,oid,fid,sha256,sd,td,ro,state,bound_at,closed_at) VALUES(?,?,?,?,?,?,?,'closed',?,?)`, p.JTI, p.OrderID, p.FileID, p.SHA256, p.StartDeadline, p.TransferDeadline, p.ResumeOffset, now(), now())
		} else {
			_, e = t.ExecContext(ctx, `UPDATE permissions SET state='closed',closed_at=? WHERE jti=?`, now(), p.JTI)
		}
		if e != nil {
			return e
		}
		return l.queueTx(ctx, t, p.OrderID, p.FileID, "complete", true)
	})
}
func (l *Ledger) Progress(ctx context.Context, id, writtenThrough int64) error {
	return tx(ctx, l.DB, func(t *sql.Tx) error {
		var p wire.Permission
		var start, end, old int64
		var open int
		e := t.QueryRowContext(ctx, `SELECT p.oid,p.fid,r.start,r.end,r.written_through,r.open FROM requests r JOIN permissions p ON p.jti=r.jti WHERE r.id=?`, id).Scan(&p.OrderID, &p.FileID, &start, &end, &old, &open)
		if e != nil {
			return e
		}
		if open != 1 || writtenThrough < old || writtenThrough > end {
			return errors.New("invalid progress")
		}
		if writtenThrough > old {
			tr, e := segments(ctx, t, "transmitted", p.OrderID, p.FileID)
			if e != nil {
				return e
			}
			tr = transform(tr, old+1, writtenThrough, 1)
			for i := range tr {
				tr[i].c = 1
			}
			if e = rewrite(ctx, t, "transmitted", p.OrderID, p.FileID, normalize(tr)); e != nil {
				return e
			}
		}
		_, e = t.ExecContext(ctx, `UPDATE requests SET written_through=? WHERE id=?`, writtenThrough, id)
		if e != nil {
			return e
		}
		if writtenThrough > old {
			return l.queueTx(ctx, t, p.OrderID, p.FileID, "in_progress", false)
		}
		return nil
	})
}
func (l *Ledger) Settle(ctx context.Context, id int64) error {
	return l.SettleOutcome(ctx, id, "")
}
func (l *Ledger) SettleOutcome(ctx context.Context, id int64, outcome string) error {
	return tx(ctx, l.DB, func(t *sql.Tx) error { return l.settle(ctx, t, id, false, outcome) })
}
func (l *Ledger) settle(ctx context.Context, t *sql.Tx, id int64, crash bool, outcome string) error {
	var p wire.Permission
	var start, end, written int64
	var open int
	e := t.QueryRowContext(ctx, `SELECT p.oid,p.fid,r.start,r.end,r.written_through,r.open FROM requests r JOIN permissions p ON p.jti=r.jti WHERE r.id=?`, id).Scan(&p.OrderID, &p.FileID, &start, &end, &written, &open)
	if e != nil {
		return e
	}
	if open == 0 {
		return nil
	}
	keep := written
	if crash {
		keep = min(end, written+window)
	}
	ss, e := segments(ctx, t, "serves", p.OrderID, p.FileID)
	if e != nil {
		return e
	}
	ss = transform(ss, max(start, keep+1), end, -1)
	if e = rewrite(ctx, t, "serves", p.OrderID, p.FileID, ss); e != nil {
		return e
	}
	if _, e = t.ExecContext(ctx, `UPDATE requests SET open=0 WHERE id=?`, id); e != nil {
		return e
	}
	tr, e := segments(ctx, t, "transmitted", p.OrderID, p.FileID)
	if e != nil {
		return e
	}
	var size int64
	e = t.QueryRowContext(ctx, `SELECT size FROM files WHERE fid=?`, p.FileID).Scan(&size)
	if e != nil {
		return e
	}
	complete := size == 0 || covered(tr, 0, size-1)
	if complete {
		if _, e = t.ExecContext(ctx, `UPDATE permissions SET state='closed',closed_at=? WHERE oid=? AND fid=? AND state IN ('issued','bound')`, now(), p.OrderID, p.FileID); e != nil {
			return e
		}
	}
	if !crash && (complete || outcome != "" || (written >= start && written < end)) {
		return l.queueTx(ctx, t, p.OrderID, p.FileID, outcome, complete)
	}
	return nil
}
func (l *Ledger) Recover(ctx context.Context) error {
	return tx(ctx, l.DB, func(t *sql.Tx) error {
		rows, e := t.QueryContext(ctx, `SELECT id FROM requests WHERE open=1`)
		if e != nil {
			return e
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		for _, id := range ids {
			if e = l.settle(ctx, t, id, true, ""); e != nil {
				return e
			}
		}
		return nil
	})
}

func (l *Ledger) Receipt(ctx context.Context, oid, fid, outcome string) (wire.Receipt, error) {
	var r wire.Receipt
	e := tx(ctx, l.DB, func(t *sql.Tx) error { var e error; r, e = l.receiptTx(ctx, t, oid, fid, outcome, 0); return e })
	return r, e
}
func (l *Ledger) receiptTx(ctx context.Context, t *sql.Tx, oid, fid, outcome string, seq uint64) (wire.Receipt, error) {
	r := wire.Receipt{Op: "receipt", OrderID: oid, FileID: fid, Outcome: outcome, BlocksVerified: outcome != "aborted_block_mismatch", JTIs: []string{}, Transmitted: []wire.Interval{}, Seq: seq}
	e := t.QueryRowContext(ctx, `SELECT sha256,size FROM files WHERE fid=?`, fid).Scan(&r.SHA256, &r.SizeBytes)
	if e != nil {
		return r, e
	}
	tr, e := segments(ctx, t, "transmitted", oid, fid)
	if e != nil {
		return r, e
	}
	for _, x := range tr {
		r.Transmitted = append(r.Transmitted, wire.Interval{x.a, x.b})
	}
	r.TransmittedBytes = countBytes(tr)
	ss, e := segments(ctx, t, "serves", oid, fid)
	if e != nil {
		return r, e
	}
	for _, x := range ss {
		if x.c == 2 {
			unwritten := x.b - x.a + 1
			for _, y := range tr {
				unwritten -= max(int64(0), min(x.b, y.b)-max(x.a, y.a)+1)
			}
			r.MaxServesReachedBytes += unwritten
		}
	}
	rows, e := t.QueryContext(ctx, `SELECT jti FROM permissions WHERE oid=? AND fid=? ORDER BY jti`, oid, fid)
	if e != nil {
		return r, e
	}
	for rows.Next() {
		var j string
		if e = rows.Scan(&j); e != nil {
			rows.Close()
			return r, e
		}
		r.JTIs = append(r.JTIs, j)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return r, e
	}
	var first, last sql.NullString
	e = t.QueryRowContext(ctx, `SELECT min(bound_at),max(closed_at) FROM permissions WHERE oid=? AND fid=?`, oid, fid).Scan(&first, &last)
	if e != nil {
		return r, e
	}
	r.FirstByteAt = first.String
	r.LastByteAt = last.String
	if r.TransmittedBytes > 0 && r.FirstByteAt == "" {
		r.FirstByteAt = now()
	}
	if r.TransmittedBytes > 0 {
		r.LastByteAt = now()
	}
	return r, nil
}
func (l *Ledger) Queue(ctx context.Context, oid, fid, outcome string) error {
	return tx(ctx, l.DB, func(t *sql.Tx) error { return l.queueTx(ctx, t, oid, fid, outcome, false) })
}
func (l *Ledger) queueTx(ctx context.Context, t *sql.Tx, oid, fid, outcome string, complete bool) error {
	if complete && outcome != "aborted_block_mismatch" && outcome != "aborted_deadline" {
		outcome = "complete"
	}
	if outcome == "" {
		outcome = "in_progress"
	}
	if outcome == "complete" {
		rows, e := t.QueryContext(ctx, `SELECT body FROM receipts_outbox`)
		if e != nil {
			return e
		}
		for rows.Next() {
			var body string
			if e = rows.Scan(&body); e != nil {
				rows.Close()
				return e
			}
			raw := []byte(body)
			if p := strings.Split(body, "."); len(p) == 3 {
				raw, _ = base64.RawURLEncoding.DecodeString(p[1])
			}
			var old wire.Receipt
			if json.Unmarshal(raw, &old) == nil && old.OrderID == oid && old.FileID == fid && old.Outcome == "complete" {
				rows.Close()
				return nil
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	var seq uint64
	e := t.QueryRowContext(ctx, `SELECT coalesce(max(seq),0)+1 FROM receipts_outbox`).Scan(&seq)
	if e != nil {
		return e
	}
	r, e := l.receiptTx(ctx, t, oid, fid, outcome, seq)
	if e != nil {
		return e
	}
	if outcome == "complete" && (r.TransmittedBytes != r.SizeBytes || !r.BlocksVerified) {
		return errors.New("incomplete receipt")
	}
	var body string
	if len(l.Key) == ed25519.PrivateKeySize {
		body, e = wire.Sign("aim-receipt+jwt", l.KID, r, l.Key)
		if e != nil {
			return e
		}
	} else {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		body = string(b)
	}
	_, e = t.ExecContext(ctx, `INSERT INTO receipts_outbox(seq,body) VALUES(?,?)`, seq, body)
	return e
}

func (l *Ledger) Prepare(ctx context.Context, i wire.Instruction, c config.Config) (wire.PrepareAck, error) {
	a := wire.PrepareAck{Op: "prepare_ack", IID: i.IID, OrderID: i.OrderID, FileID: i.FileID, MaxServeCount: 0}
	f, e := l.File(ctx, i.FileID)
	if e != nil && e != sql.ErrNoRows {
		return a, e
	}
	refusal := ""
	if e == sql.ErrNoRows {
		refusal = "file_missing"
	} else if f.Changed || f.SHA256 != i.SHA256 || !f.ValidBlocks() {
		refusal = "file_changed"
	} else if !WithinCeiling(c, f) {
		refusal = "outside_ceiling"
	} else {
		rows, e := l.DB.QueryContext(ctx, `SELECT state,key_class,approved_locally_at FROM offers WHERE fid=? AND sha256=?`, i.FileID, i.SHA256)
		if e != nil {
			return a, e
		}
		offered := false
		approved := false
		for rows.Next() {
			var state, key string
			var at sql.NullString
			if e = rows.Scan(&state, &key, &at); e != nil {
				rows.Close()
				return a, e
			}
			if state == "offered" && key == "listing" {
				offered = true
				approved = approved || at.Valid
			}
		}
		rows.Close()
		if !offered {
			refusal = "not_offered"
		} else if c.OfferRequiresLocalApproval && !approved {
			refusal = "awaiting_local_approval"
		}
	}
	e = tx(ctx, l.DB, func(t *sql.Tx) error {
		tr, e := segments(ctx, t, "transmitted", i.OrderID, i.FileID)
		if e != nil {
			return e
		}
		a.ResumeOffset = firstUntransmitted(tr, f.Size)
		a.TransmittedBytes = countBytes(tr)
		a.IntervalCount = len(tr)
		ss, e := segments(ctx, t, "serves", i.OrderID, i.FileID)
		if e != nil {
			return e
		}
		for _, x := range ss {
			a.MaxServeCount = max(a.MaxServeCount, x.c)
			if x.c == 2 && !covered(tr, x.a, x.b) && refusal == "" {
				refusal = "coverage_exhausted"
			}
		}
		if f.Size >= 0 && a.TransmittedBytes == f.Size && refusal == "" {
			refusal = "complete"
		}
		return nil
	})
	if e != nil {
		return a, e
	}
	a.Ready = refusal == ""
	if refusal != "" {
		a.Refusal = &refusal
	}
	return a, nil
}
func WithinCeiling(c config.Config, f File) bool {
	if len(c.Sources) > 0 {
		found := false
		for _, s := range c.Sources {
			if s.Name != f.Source {
				continue
			}
			root, e := filepath.EvalSymlinks(s.Path)
			if e == nil && root == f.Root {
				found = true
			}
			break
		}
		if !found {
			return false
		}
	}
	path := f.Source + "/" + f.RelativePath
	if len(c.OfferCeiling) == 0 {
		return true
	}
	for _, glob := range c.OfferCeiling {
		if strings.HasSuffix(glob, "/**") && strings.HasPrefix(path, strings.TrimSuffix(glob, "/**")+"/") {
			return true
		}
		if ok, _ := filepath.Match(glob, path); ok {
			return true
		}
	}
	return false
}

func (l *Ledger) Debug(ctx context.Context) error {
	var mode string
	if e := l.DB.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); e != nil {
		return e
	}
	if mode != "wal" {
		return fmt.Errorf("journal mode %s", mode)
	}
	return nil
}
