// Package auth handles users, sessions, bcrypt passwords, login rate-limiting,
// and session revocation for aclweb.
package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost        = 12
	sessionTTL        = 8 * time.Hour
	minPasswordLen    = 12
	rateLimitWindow   = 5 * time.Minute
	rateLimitMaxTries = 10
	sessionIDLen      = 32 // bytes → 64 hex chars
)

// ErrBadCredentials is returned on login failure (intentionally vague).
var ErrBadCredentials = errors.New("invalid username or password")

// ErrRateLimited is returned when the login rate limit is exceeded.
var ErrRateLimited = errors.New("too many login attempts")

// ErrSessionExpired is returned when a session token is expired or missing.
var ErrSessionExpired = errors.New("session expired or not found")

// Role constants mirror the DB CHECK constraint.
const (
	RoleAdmin    = "admin"
	RoleApprover = "approver"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// User is a row from the users table.
type User struct {
	ID       int64
	Username string
	Role     string
	Active   bool
}

// Service provides user and session management operations.
type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service { return &Service{db: db} }

// CreateInitialAdmin creates the first admin account if no users exist.
// The generated password is returned (printed once to stderr by the caller).
func (s *Service) CreateInitialAdmin(username string) (password string, err error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil // already bootstrapped
	}
	password = randomPassword(24)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil { return "", err }
	_, err = s.db.Exec(
		`INSERT INTO users(username, password_hash, role, active) VALUES(?,?,?,1)`,
		username, string(hash), RoleAdmin,
	)
	return password, err
}

// Login authenticates and returns a new session token.
// It enforces per-username and per-IP rate limits.
func (s *Service) Login(username, password, remoteIP string) (token string, err error) {
	// Rate-limit check (username + IP).
	for _, key := range []string{"user:" + username, "ip:" + remoteIP} {
		if err := s.checkRateLimit(key); err != nil {
			return "", err
		}
	}

	var u User
	var hash string
	err = s.db.QueryRow(
		`SELECT id, username, password_hash, role, active FROM users WHERE username=?`,
		username,
	).Scan(&u.ID, &u.Username, &hash, &u.Role, &u.Active)
	if err != nil || !u.Active {
		s.incrementRateLimit("user:"+username, "ip:"+remoteIP)
		return "", ErrBadCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		s.incrementRateLimit("user:"+username, "ip:"+remoteIP)
		return "", ErrBadCredentials
	}

	// Reset rate-limit counters on success.
	s.resetRateLimit("user:"+username, "ip:"+remoteIP)

	token = randomHex(sessionIDLen)
	exp := time.Now().Add(sessionTTL).Unix()
	_, err = s.db.Exec(
		`INSERT INTO sessions(id, user_id, expires_at) VALUES(?,?,?)`,
		token, u.ID, exp,
	)
	if err != nil { return "", err }

	_, _ = s.db.Exec(`UPDATE users SET last_login_at=? WHERE id=?`, time.Now().Unix(), u.ID)
	return token, nil
}

// ValidateSession returns the User associated with a session token, or an error.
func (s *Service) ValidateSession(token string) (*User, error) {
	var u User
	now := time.Now().Unix()
	err := s.db.QueryRow(`
		SELECT u.id, u.username, u.role, u.active
		FROM sessions ss JOIN users u ON ss.user_id = u.id
		WHERE ss.id=? AND ss.expires_at>? AND u.active=1`,
		token, now,
	).Scan(&u.ID, &u.Username, &u.Role, &u.Active)
	if err != nil {
		return nil, ErrSessionExpired
	}
	return &u, nil
}

// Logout deletes a session token.
func (s *Service) Logout(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id=?`, token)
	return err
}

// RevokeUserSessions deletes all sessions for a given user ID.
func (s *Service) RevokeUserSessions(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

// ChangePassword updates a user's password and revokes all their sessions.
// ChangePassword replaces a user's password. The current password is required:
// without it a stolen session cookie is enough to lock the owner out of their
// own account, and the change also revokes every session, which would hide the
// takeover behind what looks like an ordinary re-login.
func (s *Service) ChangePassword(userID int64, oldPassword, newPassword string) error {
	if len(newPassword) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	var current string
	if err := s.db.QueryRow(`SELECT password_hash FROM users WHERE id=?`, userID).Scan(&current); err != nil {
		return fmt.Errorf("current password check failed")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(current), []byte(oldPassword)); err != nil {
		return fmt.Errorf("current password is incorrect")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil { return err }
	tx, err := s.db.Begin()
	if err != nil { return err }
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(hash), userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// ResetPassword sets a fresh random password for a user and returns it, revoking
// every session they hold. There is no current-password check and no session to
// authenticate: this is reachable only by whoever can already open the database
// file, which is to say whoever runs the service, and it exists because the
// initial password is printed exactly once. Losing that line used to mean losing
// the only way in.
func (s *Service) ResetPassword(username string) (string, error) {
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM users WHERE username=?`, username).Scan(&id); err != nil {
		return "", fmt.Errorf("no such user: %s", username)
	}
	password := randomPassword(24)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil { return "", err }
	tx, err := s.db.Begin()
	if err != nil { return "", err }
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE users SET password_hash=?, active=1 WHERE id=?`, string(hash), id); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id=?`, id); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil { return "", err }
	return password, nil
}

// SetActive activates or deactivates a user (and revokes sessions on deactivation).
// Refuses to deactivate the last active admin.
func (s *Service) SetActive(actorID, targetID int64, active bool) error {
	if actorID == targetID && !active {
		return fmt.Errorf("cannot deactivate your own account")
	}
	if !active {
		// Guard: must not be the last active admin.
		var adminCount int
		if err := s.db.QueryRow(
			`SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND id!=?`, targetID,
		).Scan(&adminCount); err != nil { return err }
		var targetRole string
		if err := s.db.QueryRow(`SELECT role FROM users WHERE id=?`, targetID).Scan(&targetRole); err != nil {
			return err
		}
		if targetRole == RoleAdmin && adminCount == 0 {
			return fmt.Errorf("cannot deactivate the last active admin")
		}
		_, err := s.db.Exec(`UPDATE users SET active=0 WHERE id=?`, targetID)
		if err != nil { return err }
		return s.RevokeUserSessions(targetID)
	}
	_, err := s.db.Exec(`UPDATE users SET active=1 WHERE id=?`, targetID)
	return err
}

// CreateUser creates a new user. Returns an error if the username is taken.
func (s *Service) CreateUser(username, password, role string) (int64, error) {
	if len(password) < minPasswordLen {
		return 0, fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil { return 0, err }
	res, err := s.db.Exec(
		`INSERT INTO users(username, password_hash, role, active) VALUES(?,?,?,1)`,
		username, string(hash), role,
	)
	if err != nil { return 0, err }
	return res.LastInsertId()
}

// GetUser returns a user by ID.
func (s *Service) GetUser(id int64) (*User, error) {
	var u User
	err := s.db.QueryRow(`SELECT id, username, role, active FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.Role, &u.Active)
	if err != nil { return nil, err }
	return &u, nil
}

// PurgeExpiredSessions removes sessions that have passed their expiry time.
func (s *Service) PurgeExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at<?`, time.Now().Unix())
	return err
}

// ─── rate limiting ───────────────────────────────────────────────────────────

func (s *Service) checkRateLimit(key string) error {
	now := time.Now().Unix()
	var count int
	var windowEnd int64
	err := s.db.QueryRow(
		`SELECT count, window_end FROM rate_limits WHERE key=?`, key,
	).Scan(&count, &windowEnd)
	if err != nil || windowEnd < now { return nil } // no record or expired window
	if count >= rateLimitMaxTries { return ErrRateLimited }
	return nil
}

func (s *Service) incrementRateLimit(keys ...string) {
	now := time.Now().Unix()
	windowEnd := now + int64(rateLimitWindow.Seconds())
	for _, key := range keys {
		s.db.Exec(`
			INSERT INTO rate_limits(key, count, window_end) VALUES(?,1,?)
			ON CONFLICT(key) DO UPDATE SET
			  count = CASE WHEN window_end < ? THEN 1 ELSE count+1 END,
			  window_end = CASE WHEN window_end < ? THEN ? ELSE window_end END`,
			key, windowEnd, now, now, windowEnd,
		)
	}
}

func (s *Service) resetRateLimit(keys ...string) {
	for _, key := range keys {
		s.db.Exec(`DELETE FROM rate_limits WHERE key=?`, key)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil { panic(err) }
	return hex.EncodeToString(b)
}

func randomPassword(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, n)
	rand.Read(b)
	for i, c := range b { b[i] = chars[int(c)%len(chars)] }
	return string(b)
}
