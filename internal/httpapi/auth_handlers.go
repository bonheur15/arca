package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"time"

	"arca/internal/accounts"
	"arca/internal/app"
	"arca/internal/auth"

	"github.com/go-chi/chi/v5"
)

func (s *Server) bootstrapStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.runtime.Bootstrap.Status(r.Context())
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	allowAccessRequests := true
	if status.Initialized {
		if err := s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT allow_access_requests FROM instance_settings WHERE singleton = 1`).Scan(&allowAccessRequests); err != nil {
			s.handleError(w, r, err)
			return
		}
	}
	response := map[string]any{
		"initialized": status.Initialized, "setup_required": status.SetupRequired,
		"instance_name":         s.runtime.Config.File.InstanceName,
		"allow_access_requests": allowAccessRequests,
	}
	if !status.Initialized && !status.ExpiresAt.IsZero() {
		response["setup_expires_at"] = status.ExpiresAt
	}
	if status.Initialized {
		response["public_url"] = s.runtime.Config.File.PublicURL
	}
	WriteJSON(w, http.StatusOK, response)
}

func (s *Server) bootstrapValidate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "Enter the setup code printed by the Arca server.")
		return
	}
	if err := s.runtime.Bootstrap.ValidateCode(r.Context(), body.Code); err != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "invalid_setup_code", "Invalid setup code", "The setup code is invalid or expired.")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (s *Server) bootstrapStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SetupCode      string `json:"setupCode"`
		SetupCodeAlt   string `json:"setup_code"`
		InstanceName   string `json:"instanceName"`
		InstanceAlt    string `json:"instance_name"`
		PublicURL      string `json:"publicUrl"`
		PublicURLAlt   string `json:"public_url"`
		WorkOSClientID string `json:"workosClientId"`
		ClientIDAlt    string `json:"workos_client_id"`
		WorkOSAPIKey   string `json:"workosApiKey"`
		APIKeyAlt      string `json:"workos_api_key"`
		Username       string `json:"username"`
		Email          string `json:"email"`
		DisplayName    string `json:"displayName"`
		QuotaBytes     int64  `json:"quotaBytes"`
		QuotaUnlimited bool   `json:"quotaUnlimited"`
		Superadmin     *struct {
			Username       string `json:"username"`
			Email          string `json:"email"`
			DisplayName    string `json:"displayName"`
			QuotaBytes     int64  `json:"quotaBytes"`
			QuotaUnlimited bool   `json:"quotaUnlimited"`
		} `json:"superadmin"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	first := func(values ...string) string {
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return value
			}
		}
		return ""
	}
	input := appBootstrapInput(body.SetupCode, body.InstanceName, body.PublicURL, body.WorkOSClientID, body.WorkOSAPIKey, body.Username, body.Email, body.DisplayName, body.QuotaBytes, body.QuotaUnlimited)
	input.SetupCode = first(body.SetupCode, body.SetupCodeAlt)
	input.InstanceName = first(body.InstanceName, body.InstanceAlt)
	input.PublicURL = first(body.PublicURL, body.PublicURLAlt)
	input.WorkOSClientID = first(body.WorkOSClientID, body.ClientIDAlt)
	input.WorkOSAPIKey = first(body.WorkOSAPIKey, body.APIKeyAlt)
	if body.Superadmin != nil {
		input.Username = body.Superadmin.Username
		input.Email = body.Superadmin.Email
		input.DisplayName = body.Superadmin.DisplayName
		input.QuotaBytes = body.Superadmin.QuotaBytes
		input.QuotaUnlimited = body.Superadmin.QuotaUnlimited
	}
	expires, err := s.runtime.Bootstrap.Configure(r.Context(), input, s.remoteIP(r), r.UserAgent())
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, map[string]any{"challenge_expires_at": expires, "message": "Check the superadmin email for the six-digit WorkOS sign-in code."})
}

func appBootstrapInput(setup, name, publicURL, clientID, apiKey, username, email, display string, quota int64, unlimited bool) app.BootstrapConfigureInput {
	return app.BootstrapConfigureInput{SetupCode: setup, InstanceName: name, PublicURL: publicURL, WorkOSClientID: clientID, WorkOSAPIKey: apiKey, Username: username, Email: email, DisplayName: display, QuotaBytes: quota, QuotaUnlimited: unlimited}
}

func (s *Server) bootstrapVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SetupCode    string `json:"setupCode"`
		SetupCodeAlt string `json:"setup_code"`
		Code         string `json:"code"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if body.SetupCode == "" {
		body.SetupCode = body.SetupCodeAlt
	}
	result, err := s.runtime.Bootstrap.Verify(r.Context(), body.SetupCode, body.Code)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.setAuthenticatedCookies(w, result)
	WriteJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": result.User, "csrf_token": result.CSRFToken})
}

func (s *Server) magicStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	_ = decodeBody(w, r, &body)
	result, err := s.runtime.Authentication.StartMagic(r.Context(), auth.MagicStartRequest{Email: body.Email, IPAddress: s.remoteIP(r), UserAgent: r.UserAgent()})
	policy := s.cookiePolicy()
	if err == nil && result != nil {
		policy.SetChallenge(w, result.ChallengeToken, result.ExpiresAt)
	} else {
		// Preserve the same externally observable response for unknown, invalid,
		// throttled, and temporarily unavailable identities.
		policy.SetChallenge(w, randomID(32), time.Now().Add(10*time.Minute))
	}
	WriteJSON(w, http.StatusAccepted, map[string]any{"message": "If the account is active, a six-digit sign-in code has been sent.", "expires_in": 600})
}

func (s *Server) magicVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid credentials", "The supplied credentials are invalid or expired.")
		return
	}
	policy := s.cookiePolicy()
	challenge, err := auth.ReadCookie(r, policy.ChallengeName())
	if err != nil {
		WriteProblem(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid credentials", "The supplied credentials are invalid or expired.")
		return
	}
	result, err := s.runtime.Authentication.VerifyMagic(r.Context(), challenge, body.Code)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.setAuthenticatedCookies(w, result)
	WriteJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": result.User, "csrf_token": result.CSRFToken})
}

func (s *Server) setAuthenticatedCookies(w http.ResponseWriter, result *auth.MagicVerifyResult) {
	policy := s.cookiePolicy()
	expires := time.Now().Add(30 * 24 * time.Hour)
	policy.SetSession(w, result.SealedSession, expires)
	policy.SetCSRF(w, result.CSRFToken, expires)
	// Clear the one-use challenge while preserving the new session cookies.
	http.SetCookie(w, &http.Cookie{Name: policy.ChallengeName(), Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), HttpOnly: true, Secure: policy.Secure, SameSite: http.SameSiteLaxMode})
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	authenticated, err := s.authenticate(w, r)
	if err != nil {
		if errors.Is(err, auth.ErrSessionUnavailable) {
			WriteProblem(w, r, http.StatusServiceUnavailable, "authentication_unavailable", "Authentication temporarily unavailable", "Your session was preserved. Try again shortly.")
			return
		}
		s.cookiePolicy().ClearAuth(w)
		WriteJSON(w, http.StatusOK, map[string]any{"authenticated": false, "user": nil, "csrf_token": nil})
		return
	}
	user, err := s.runtime.AccountRepo.GetUserByID(r.Context(), authenticated.UserID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": user, "csrf_token": authenticated.CSRFToken})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	policy := s.cookiePolicy()
	sealed, _ := auth.ReadCookie(r, policy.SessionName())
	err := s.runtime.Authentication.Logout(r.Context(), sealed)
	policy.ClearAuth(w)
	if err != nil && !errors.Is(err, auth.ErrUnauthenticated) {
		s.logger.Warn("remote logout failed after local cookie clear", "request_id", RequestID(r.Context()), "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	items, err := s.runtime.Authentication.ListSessions(r.Context(), p.UserID, p.UserID, 100)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	for index := range items {
		// WorkOS may report multiple active sessions; identify only the actual
		// sealed session held by this request.
		if items[index].ID == p.SessionID {
			items[index].Status = "current"
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	sessionID := chi.URLParam(r, "sessionID")
	if err := s.runtime.Authentication.RevokeSession(r.Context(), sessionID, p.UserID, time.Now().Add(30*24*time.Hour), mutation(r, s.remoteIP(r))); err != nil {
		s.handleError(w, r, err)
		return
	}
	if sessionID == p.SessionID {
		s.cookiePolicy().ClearAuth(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requestAccess(w http.ResponseWriter, r *http.Request) {
	var allowed, initialized bool
	if err := s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT allow_access_requests, initialized FROM instance_settings WHERE singleton = 1`).Scan(&allowed, &initialized); err != nil {
		s.handleError(w, r, err)
		return
	}
	if !initialized || !allowed {
		WriteProblem(w, r, http.StatusNotFound, "access_requests_disabled", "Access requests unavailable", "This Arca instance is not accepting account requests.")
		return
	}
	var body struct {
		Username    string `json:"username"`
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
		Reason      string `json:"reason"`
		Website     string `json:"website"`
		StartedAt   int64  `json:"startedAt"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if body.Website != "" || body.StartedAt <= 0 || time.Since(time.UnixMilli(body.StartedAt)) < 1500*time.Millisecond {
		WriteJSON(w, http.StatusAccepted, map[string]any{"status_token": randomID(32), "state": "pending"})
		return
	}
	mac := hmac.New(sha256.New, s.runtime.CSRFSecret)
	_, _ = mac.Write([]byte(s.remoteIP(r)))
	result, err := s.runtime.Accounts.RequestAccess(r.Context(), accounts.CreateAccessRequestParams{Username: body.Username, Email: body.Email, DisplayName: body.DisplayName, Reason: body.Reason, RequesterIPHash: mac.Sum(nil)}, accounts.MutationContext{IPAddress: s.remoteIP(r), UserAgent: r.UserAgent(), RequestID: RequestID(r.Context())})
	if err != nil {
		if errors.Is(err, accounts.ErrConflict) {
			WriteJSON(w, http.StatusAccepted, map[string]any{"status_token": randomID(32), "state": "pending"})
			return
		}
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, map[string]any{"status_token": result.StatusToken, "state": result.Request.State})
}

func (s *Server) accessRequestStatus(w http.ResponseWriter, r *http.Request) {
	request, err := s.runtime.Accounts.RequestStatus(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		// Status tokens are opaque; avoid distinguishing malformed and unknown.
		WriteProblem(w, r, http.StatusNotFound, "status_unavailable", "Status unavailable", "This status link is invalid or expired.")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"state": request.State})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, err := s.runtime.AccountRepo.GetUserByID(r.Context(), principal(r).UserID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, user)
}

func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DisplayName string `json:"displayName"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	p := principal(r)
	user, err := s.runtime.Accounts.UpdateProfile(r.Context(), p.UserID, accounts.ProfileUpdate{DisplayName: &body.DisplayName}, mutation(r, s.remoteIP(r)))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, user)
}

func (s *Server) updatePreferences(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ThemeMode     accounts.ThemeMode `json:"themeMode"`
		ThemeModeAlt  accounts.ThemeMode `json:"theme_mode"`
		Accent        string             `json:"accent"`
		Density       accounts.Density   `json:"density"`
		ReducedMotion bool               `json:"reducedMotion"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if body.ThemeMode == "" {
		body.ThemeMode = body.ThemeModeAlt
	}
	p := principal(r)
	user, err := s.runtime.Accounts.UpdatePreferences(r.Context(), p.UserID, accounts.Preferences{ThemeMode: body.ThemeMode, Accent: body.Accent, Density: body.Density, ReducedMotion: body.ReducedMotion}, mutation(r, s.remoteIP(r)))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, user.Preferences)
}

func (s *Server) lookupUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.runtime.AccountRepo.GetUserByUsernameOrEmail(r.Context(), r.URL.Query().Get("q"))
	if err != nil || !user.State.CanAuthenticate() {
		WriteProblem(w, r, http.StatusNotFound, "not_found", "User not found", "No active Arca user matches that username or email.")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"id": user.ID, "username": user.Username, "email": user.Email, "display_name": user.DisplayName})
}
