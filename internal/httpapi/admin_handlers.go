package httpapi

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"arca/internal/accounts"
	"arca/internal/audit"
	"arca/internal/auth"
	"arca/internal/config"

	"github.com/go-chi/chi/v5"
)

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeTokensManage)) {
		return
	}
	p := principal(r)
	items, err := s.runtime.Tokens.List(r.Context(), p.UserID, p.UserID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeTokensManage)) {
		return
	}
	var body struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresAt string   `json:"expiresAt"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	expires, err := parseTimePointer(body.ExpiresAt)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_expiry", "Invalid expiration", "expiresAt must be an RFC3339 timestamp.")
		return
	}
	scopes := make([]auth.Scope, 0, len(body.Scopes))
	for _, scope := range body.Scopes {
		scopes = append(scopes, auth.Scope(scope))
	}
	p := principal(r)
	created, err := s.runtime.Tokens.Create(r.Context(), p.UserID, body.Name, scopes, expires, mutation(r, s.remoteIP(r)))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, created)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeTokensManage)) {
		return
	}
	p := principal(r)
	if err := s.runtime.Tokens.Revoke(r.Context(), chi.URLParam(r, "tokenID"), p.UserID, mutation(r, s.remoteIP(r))); err != nil {
		s.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) notifications(w http.ResponseWriter, r *http.Request) {
	rows, err := s.runtime.Database.Reader().QueryContext(r.Context(), `SELECT id, kind, payload, read_at, created_at
		FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`, principal(r).UserID, queryLimit(r))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, kind, payload, created string
		var readAt sql.NullString
		if err := rows.Scan(&id, &kind, &payload, &readAt, &created); err != nil {
			s.handleError(w, r, err)
			return
		}
		var decoded any
		_ = json.Unmarshal([]byte(payload), &decoded)
		items = append(items, map[string]any{"id": id, "kind": kind, "payload": decoded, "read_at": nullableSQLString(readAt), "created_at": created})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	items, err := s.runtime.AccountRepo.ListUsers(r.Context(), queryLimit(r), r.URL.Query().Get("cursor"))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username       string        `json:"username"`
		Email          string        `json:"email"`
		DisplayName    string        `json:"displayName"`
		Role           accounts.Role `json:"role"`
		QuotaBytes     int64         `json:"quotaBytes"`
		QuotaUnlimited bool          `json:"quotaUnlimited"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if body.Role == "" {
		body.Role = accounts.RoleMember
	}
	created, err := s.runtime.Accounts.CreateUser(r.Context(), accounts.CreateUserParams{Username: body.Username, Email: body.Email, DisplayName: body.DisplayName, Role: body.Role, QuotaBytes: body.QuotaBytes, QuotaUnlimited: body.QuotaUnlimited, Policy: accounts.DefaultPolicy()}, mutation(r, s.remoteIP(r)))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, created)
}

func (s *Server) adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action         string         `json:"action"`
		Role           *accounts.Role `json:"role"`
		QuotaBytes     *int64         `json:"quotaBytes"`
		QuotaUnlimited *bool          `json:"quotaUnlimited"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	userID := chi.URLParam(r, "userID")
	mutation := mutation(r, s.remoteIP(r))
	var user *accounts.User
	var err error
	if body.Role != nil {
		user, err = s.runtime.Accounts.SetRole(r.Context(), userID, *body.Role, mutation)
	}
	if err == nil && (body.QuotaBytes != nil || body.QuotaUnlimited != nil) {
		current, getErr := s.runtime.AccountRepo.GetUserByID(r.Context(), userID)
		if getErr != nil {
			err = getErr
		} else {
			policy, policyErr := s.runtime.AccountRepo.GetPolicy(r.Context(), userID)
			if policyErr != nil {
				err = policyErr
			} else {
				quota := current.QuotaBytes
				unlimited := current.QuotaUnlimited
				if body.QuotaBytes != nil {
					quota = *body.QuotaBytes
				}
				if body.QuotaUnlimited != nil {
					unlimited = *body.QuotaUnlimited
				}
				user, err = s.runtime.Accounts.UpdatePolicyAndQuota(r.Context(), userID, quota, unlimited, policy, mutation)
			}
		}
	}
	if err == nil {
		switch body.Action {
		case "":
		case "suspend":
			user, err = s.runtime.Accounts.SuspendUser(r.Context(), userID, mutation)
		case "activate", "restore":
			user, err = s.runtime.Accounts.RestoreUser(r.Context(), userID, mutation)
		case "delete":
			user, err = s.runtime.Accounts.ScheduleDeletion(r.Context(), userID, mutation)
		default:
			err = accounts.ErrInvalidInput
		}
	}
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	if user == nil {
		user, err = s.runtime.AccountRepo.GetUserByID(r.Context(), userID)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
	}
	WriteJSON(w, http.StatusOK, user)
}

func (s *Server) adminRequests(w http.ResponseWriter, r *http.Request) {
	items, err := s.runtime.AccountRepo.ListAccessRequests(r.Context(), accounts.AccessRequestState(r.URL.Query().Get("state")), queryLimit(r), r.URL.Query().Get("cursor"))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminDecideRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action         string `json:"action"`
		Username       string `json:"username"`
		DisplayName    string `json:"displayName"`
		QuotaBytes     int64  `json:"quotaBytes"`
		QuotaUnlimited bool   `json:"quotaUnlimited"`
		Note           string `json:"note"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	id := chi.URLParam(r, "requestID")
	mutation := mutation(r, s.remoteIP(r))
	switch body.Action {
	case "approve":
		user, err := s.runtime.Accounts.ApproveAccessRequest(r.Context(), accounts.ReserveApprovalParams{RequestID: id, Username: body.Username, DisplayName: body.DisplayName, QuotaBytes: body.QuotaBytes, QuotaUnlimited: body.QuotaUnlimited, Policy: accounts.DefaultPolicy()}, body.Note, mutation)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, user)
	case "reject":
		request, err := s.runtime.Accounts.RejectAccessRequest(r.Context(), id, body.Note, mutation)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, request)
	default:
		WriteProblem(w, r, http.StatusBadRequest, "invalid_action", "Invalid action", "Use approve or reject.")
	}
}

type policyBody struct {
	QuotaBytes            int64    `json:"quotaBytes"`
	Unlimited             bool     `json:"unlimited"`
	MaxFileBytes          *int64   `json:"maxFileBytes"`
	MaxItems              int64    `json:"maxItems"`
	AllowInternalSharing  bool     `json:"allowInternalSharing"`
	AllowPublicSharing    bool     `json:"allowPublicSharing"`
	AllowAPITokens        bool     `json:"allowApiTokens"`
	MaxConcurrentUploads  int      `json:"maxConcurrentUploads"`
	MaxPendingUploads     int      `json:"maxPendingUploads"`
	MaxActivePublicShares int      `json:"maxActivePublicShares"`
	MaxPublicTTLMinutes   int      `json:"maxPublicTtlMinutes"`
	MaxPublicRedemptions  int      `json:"maxPublicRedemptions"`
	AllowedMIMEGroups     []string `json:"allowedMimeGroups"`
	BlockedExtensions     []string `json:"blockedExtensions"`
	UploadRateBytes       *int64   `json:"uploadRateBytes"`
	DownloadRateBytes     *int64   `json:"downloadRateBytes"`
}

func (s *Server) adminPolicy(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	user, err := s.runtime.AccountRepo.GetUserByID(r.Context(), userID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	policy, err := s.runtime.AccountRepo.GetPolicy(r.Context(), userID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, policyResponse(user, policy))
}

func (s *Server) adminSavePolicy(w http.ResponseWriter, r *http.Request) {
	var body policyBody
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	userID := chi.URLParam(r, "userID")
	existing, err := s.runtime.AccountRepo.GetPolicy(r.Context(), userID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	policy := existing
	policy.MaxFileBytes = body.MaxFileBytes
	policy.MaxItems = body.MaxItems
	policy.AllowInternalSharing = body.AllowInternalSharing
	policy.AllowPublicSharing = body.AllowPublicSharing
	policy.AllowAPITokens = body.AllowAPITokens
	policy.MaxConcurrentUploads = body.MaxConcurrentUploads
	policy.MaxPendingUploads = body.MaxPendingUploads
	policy.MaxActivePublicShares = body.MaxActivePublicShares
	policy.MaxPublicTTLMinutes = body.MaxPublicTTLMinutes
	policy.MaxPublicRedemptions = body.MaxPublicRedemptions
	policy.AllowedMIMEGroups = body.AllowedMIMEGroups
	policy.BlockedExtensions = body.BlockedExtensions
	policy.UploadRateBytes = body.UploadRateBytes
	policy.DownloadRateBytes = body.DownloadRateBytes
	user, err := s.runtime.Accounts.UpdatePolicyAndQuota(r.Context(), userID, body.QuotaBytes, body.Unlimited, policy, mutation(r, s.remoteIP(r)))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, policyResponse(user, policy))
}

func policyResponse(user *accounts.User, policy accounts.Policy) map[string]any {
	return map[string]any{"quotaBytes": user.QuotaBytes, "unlimited": user.QuotaUnlimited, "maxFileBytes": policy.MaxFileBytes,
		"maxItems": policy.MaxItems, "allowInternalSharing": policy.AllowInternalSharing, "allowPublicSharing": policy.AllowPublicSharing,
		"allowApiTokens": policy.AllowAPITokens, "maxConcurrentUploads": policy.MaxConcurrentUploads, "maxPendingUploads": policy.MaxPendingUploads,
		"maxActivePublicShares": policy.MaxActivePublicShares, "maxPublicTtlMinutes": policy.MaxPublicTTLMinutes,
		"maxPublicRedemptions": policy.MaxPublicRedemptions, "allowedMimeGroups": policy.AllowedMIMEGroups,
		"blockedExtensions": policy.BlockedExtensions, "uploadRateBytes": policy.UploadRateBytes, "downloadRateBytes": policy.DownloadRateBytes}
}

func (s *Server) adminStorage(w http.ResponseWriter, r *http.Request) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.runtime.Config.Layout.Root, &stat); err != nil {
		s.handleError(w, r, err)
		return
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	availableRaw := int64(stat.Bavail) * int64(stat.Bsize)
	available := availableRaw - s.runtime.Config.File.FilesystemReserveBytes
	if available < 0 {
		available = 0
	}
	var used, reserved, blobCount, orphanCount, failedJobs int64
	_ = s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT COALESCE(SUM(used_bytes),0), COALESCE(SUM(reserved_bytes),0) FROM users WHERE state <> 'deleted'`).Scan(&used, &reserved)
	_ = s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT COUNT(*), COALESCE(SUM(CASE WHEN ref_count = 0 THEN 1 ELSE 0 END),0) FROM blobs`).Scan(&blobCount, &orphanCount)
	_ = s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT COUNT(*) FROM jobs WHERE state = 'dead'`).Scan(&failedJobs)
	var trashBytes, versionBytes int64
	_ = s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT COALESCE(SUM(size_bytes),0) FROM nodes WHERE trashed_at IS NOT NULL AND kind = 'file'`).Scan(&trashBytes)
	_ = s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT COALESCE(SUM(v.size_bytes),0) FROM file_versions v JOIN nodes n ON n.id = v.node_id WHERE v.id <> n.current_version_id`).Scan(&versionBytes)
	walBytes := int64(0)
	if info, err := os.Stat(s.runtime.Config.Layout.Database + "-wal"); err == nil {
		walBytes = info.Size()
	}
	WriteJSON(w, http.StatusOK, map[string]any{"totalBytes": total, "availableBytes": available, "usedBytes": used, "reservedBytes": reserved,
		"trashBytes": trashBytes, "versionBytes": versionBytes, "blobCount": blobCount, "orphanCount": orphanCount,
		"walBytes": walBytes, "failedJobs": failedJobs, "lastBackupAt": nil})
}

func (s *Server) adminJobs(w http.ResponseWriter, r *http.Request) {
	items, err := s.runtime.Jobs.List(r.Context(), queryLimit(r))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminRetryJob(w http.ResponseWriter, r *http.Request) {
	if err := s.runtime.Jobs.Retry(r.Context(), chi.URLParam(r, "jobID")); err != nil {
		s.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := s.runtime.Database.Reader().QueryContext(r.Context(), `SELECT e.id, e.action, e.target_type, e.target_id, e.ip_address,
		e.created_at, u.id, u.username, u.display_name FROM audit_events e LEFT JOIN users u ON u.id = e.actor_id ORDER BY e.created_at DESC LIMIT ?`, queryLimit(r))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	defer rows.Close()
	type event struct {
		ID, Action, TargetType, TargetID, IP, Created string
		Actor                                         any
	}
	items := make([]event, 0)
	for rows.Next() {
		var item event
		var targetType, targetID, ip, actorID, username, display sql.NullString
		if err := rows.Scan(&item.ID, &item.Action, &targetType, &targetID, &ip, &item.Created, &actorID, &username, &display); err != nil {
			s.handleError(w, r, err)
			return
		}
		item.TargetType, item.TargetID, item.IP = targetType.String, targetID.String, ip.String
		if actorID.Valid {
			item.Actor = map[string]any{"id": actorID.String, "username": username.String, "display_name": display.String}
		}
		items = append(items, item)
	}
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="arca-audit.csv"`)
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"id", "created_at", "action", "target_type", "target_id", "ip_address"})
		for _, item := range items {
			_ = writer.Write([]string{csvSafe(item.ID), csvSafe(item.Created), csvSafe(item.Action), csvSafe(item.TargetType), csvSafe(item.TargetID), csvSafe(item.IP)})
		}
		writer.Flush()
		return
	}
	response := make([]map[string]any, 0, len(items))
	for _, item := range items {
		response = append(response, map[string]any{"id": item.ID, "action": item.Action, "actor": item.Actor, "target_type": nullableString(item.TargetType), "target_id": nullableString(item.TargetID), "summary": strings.ReplaceAll(item.Action, ".", " "), "ip_address": nullableString(item.IP), "created_at": item.Created})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": response})
}

func csvSafe(value string) string {
	if value != "" && strings.ContainsRune("=+-@", rune(value[0])) {
		return "'" + value
	}
	return value
}

func (s *Server) adminSettings(w http.ResponseWriter, r *http.Request) {
	var allow bool
	var trustedJSON, originsJSON string
	if err := s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT allow_access_requests, trusted_proxy_cidrs, allowed_cors_origins FROM instance_settings WHERE singleton = 1`).Scan(&allow, &trustedJSON, &originsJSON); err != nil {
		s.handleError(w, r, err)
		return
	}
	var trusted []string
	_ = json.Unmarshal([]byte(trustedJSON), &trusted)
	var origins []string
	_ = json.Unmarshal([]byte(originsJSON), &origins)
	WriteJSON(w, http.StatusOK, map[string]any{"instanceName": s.runtime.Config.File.InstanceName, "publicUrl": s.runtime.Config.File.PublicURL,
		"allowAccessRequests": allow, "filesystemReserveBytes": s.runtime.Config.File.FilesystemReserveBytes, "trustedProxyCidrs": trusted, "allowedCorsOrigins": origins})
}

func (s *Server) adminSaveSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		InstanceName           string   `json:"instanceName"`
		PublicURL              string   `json:"publicUrl"`
		AllowAccessRequests    bool     `json:"allowAccessRequests"`
		FilesystemReserveBytes int64    `json:"filesystemReserveBytes"`
		TrustedProxyCIDRs      []string `json:"trustedProxyCidrs"`
		AllowedCORSOrigins     []string `json:"allowedCorsOrigins"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if strings.TrimSpace(body.InstanceName) == "" || body.FilesystemReserveBytes < 0 {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_settings", "Invalid settings", "Instance name and a non-negative reserve are required.")
		return
	}
	parsed, err := url.Parse(body.PublicURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !isLoopbackURL(parsed)) {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_public_url", "Invalid public URL", "Use HTTPS except for a loopback development URL.")
		return
	}
	if _, err := ParseCIDRs(body.TrustedProxyCIDRs); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_proxy_cidrs", "Invalid trusted proxies", err.Error())
		return
	}
	if _, err := ParseOrigins(body.AllowedCORSOrigins); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_cors_origins", "Invalid CORS origins", err.Error())
		return
	}
	trusted, _ := json.Marshal(body.TrustedProxyCIDRs)
	origins, _ := json.Marshal(body.AllowedCORSOrigins)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.runtime.Database.Writer().ExecContext(r.Context(), `UPDATE instance_settings SET name=?, public_url=?, filesystem_reserve_bytes=?, allow_access_requests=?, trusted_proxy_cidrs=?, allowed_cors_origins=?, updated_at=? WHERE singleton=1`, body.InstanceName, body.PublicURL, body.FilesystemReserveBytes, body.AllowAccessRequests, string(trusted), string(origins), now)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.runtime.Config.File.InstanceName = body.InstanceName
	s.runtime.Config.File.PublicURL = body.PublicURL
	s.runtime.Config.File.FilesystemReserveBytes = body.FilesystemReserveBytes
	s.runtime.Config.File.TrustedProxyCIDRs = body.TrustedProxyCIDRs
	s.runtime.Config.File.AllowedCORSOrigins = body.AllowedCORSOrigins
	if err := s.runtime.Config.Save(); err != nil {
		s.handleError(w, r, err)
		return
	}
	p := principal(r)
	_ = s.runtime.Audit.Record(r.Context(), audit.Event{ActorID: &p.UserID, Action: "instance.settings_changed", TargetType: "instance", TargetID: "1", IPAddress: s.remoteIP(r), UserAgent: r.UserAgent(), RequestID: RequestID(r.Context())})
	WriteJSON(w, http.StatusOK, map[string]any{"saved": true, "restart_required": true})
}

func isLoopbackURL(parsed *url.URL) bool {
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (s *Server) adminSupportAccess(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TargetUserID string `json:"targetUserId"`
		Reason       string `json:"reason"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	access, err := s.runtime.Accounts.GrantSupportAccess(r.Context(), body.TargetUserID, body.Reason, mutation(r, s.remoteIP(r)))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, access)
}

func nullableSQLString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

var _ = errors.Is
var _ = fmt.Sprint
var _ = strconv.Itoa
var _ = config.DefaultDataDir
