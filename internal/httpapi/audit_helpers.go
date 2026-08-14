package httpapi

import (
	"errors"
	"net/http"

	"arca/internal/audit"
)

func (s *Server) recordRequestAudit(r *http.Request, action, targetType, targetID string, metadata map[string]any) error {
	if s.runtime.Audit == nil {
		return errors.New("audit recorder is unavailable")
	}
	p, authenticated := GetPrincipal(r.Context())
	var actorID *string
	if authenticated && p.UserID != "" {
		actor := p.UserID
		actorID = &actor
	}
	return s.runtime.Audit.Record(r.Context(), audit.Event{
		ActorID: actorID, Action: action, TargetType: targetType, TargetID: targetID,
		IPAddress: s.remoteIP(r), UserAgent: r.UserAgent(), RequestID: RequestID(r.Context()), Metadata: metadata,
	})
}
