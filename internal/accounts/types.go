// Package accounts owns Arca's local account, policy, access-request, and
// appearance-preference state. Authentication identity remains owned by the
// configured identity provider.
package accounts

import (
	"errors"
	"time"
)

var (
	ErrNotFound           = errors.New("accounts: not found")
	ErrConflict           = errors.New("accounts: value already exists")
	ErrInvalidInput       = errors.New("accounts: invalid input")
	ErrForbidden          = errors.New("accounts: forbidden")
	ErrLastSuperadmin     = errors.New("accounts: cannot remove the final active superadmin")
	ErrInvalidTransition  = errors.New("accounts: invalid state transition")
	ErrRequestDecided     = errors.New("accounts: access request has already been decided")
	ErrInvalidStatusToken = errors.New("accounts: invalid status token")
)

type Role string

const (
	RoleSuperadmin Role = "superadmin"
	RoleMember     Role = "member"
)

func (r Role) Valid() bool { return r == RoleSuperadmin || r == RoleMember }

type State string

const (
	StateProvisioning    State = "provisioning"
	StateActive          State = "active"
	StateSuspended       State = "suspended"
	StateOverQuota       State = "over_quota"
	StateDeletionPending State = "deletion_pending"
	StateDeleted         State = "deleted"
)

func (s State) Valid() bool {
	switch s {
	case StateProvisioning, StateActive, StateSuspended, StateOverQuota, StateDeletionPending, StateDeleted:
		return true
	default:
		return false
	}
}

func (s State) CanAuthenticate() bool { return s == StateActive || s == StateOverQuota }

type ThemeMode string

const (
	ThemeSystem ThemeMode = "system"
	ThemeLight  ThemeMode = "light"
	ThemeDark   ThemeMode = "dark"
)

type Density string

const (
	DensityCompact     Density = "compact"
	DensityComfortable Density = "comfortable"
)

var AllowedAccents = map[string]struct{}{
	"violet": {}, "indigo": {}, "blue": {}, "cyan": {},
	"teal": {}, "green": {}, "amber": {}, "rose": {},
}

type Preferences struct {
	ThemeMode     ThemeMode `json:"theme_mode"`
	Accent        string    `json:"accent"`
	Density       Density   `json:"density"`
	ReducedMotion bool      `json:"reduced_motion"`
}

func DefaultPreferences() Preferences {
	return Preferences{ThemeMode: ThemeSystem, Accent: "violet", Density: DensityComfortable}
}

type Policy struct {
	MaxFileBytes          *int64    `json:"max_file_bytes,omitempty"`
	MaxItems              int64     `json:"max_items"`
	AllowInternalSharing  bool      `json:"allow_internal_sharing"`
	AllowPublicSharing    bool      `json:"allow_public_sharing"`
	AllowAPITokens        bool      `json:"allow_api_tokens"`
	MaxConcurrentUploads  int       `json:"max_concurrent_uploads"`
	MaxPendingUploads     int       `json:"max_pending_uploads"`
	MaxActivePublicShares int       `json:"max_active_public_shares"`
	MaxPublicTTLMinutes   int       `json:"max_public_ttl_minutes"`
	MaxPublicRedemptions  int       `json:"max_public_redemptions"`
	AllowedMIMEGroups     []string  `json:"allowed_mime_groups"`
	BlockedExtensions     []string  `json:"blocked_extensions"`
	UploadRateBytes       *int64    `json:"upload_rate_bytes,omitempty"`
	DownloadRateBytes     *int64    `json:"download_rate_bytes,omitempty"`
	UpdatedAt             time.Time `json:"updated_at"`
}

func DefaultPolicy() Policy {
	return Policy{
		MaxItems: 100_000, AllowInternalSharing: true, AllowPublicSharing: true,
		AllowAPITokens: true, MaxConcurrentUploads: 3, MaxPendingUploads: 20,
		MaxActivePublicShares: 10, MaxPublicTTLMinutes: 30,
		MaxPublicRedemptions: 10, AllowedMIMEGroups: []string{},
		BlockedExtensions: []string{},
	}
}

type User struct {
	ID             string      `json:"id"`
	WorkOSUserID   string      `json:"workos_user_id,omitempty"`
	Username       string      `json:"username"`
	UsernameKey    string      `json:"-"`
	Email          string      `json:"email"`
	EmailKey       string      `json:"-"`
	DisplayName    string      `json:"display_name,omitempty"`
	Role           Role        `json:"role"`
	State          State       `json:"state"`
	QuotaBytes     int64       `json:"quota_bytes"`
	QuotaUnlimited bool        `json:"quota_unlimited"`
	UsedBytes      int64       `json:"used_bytes"`
	ReservedBytes  int64       `json:"reserved_bytes"`
	RootNodeID     string      `json:"root_node_id"`
	Preferences    Preferences `json:"preferences"`
	LastSignInAt   *time.Time  `json:"last_sign_in_at,omitempty"`
	DeletionDueAt  *time.Time  `json:"deletion_due_at,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

type AccessRequestState string

const (
	AccessRequestPending  AccessRequestState = "pending"
	AccessRequestApproved AccessRequestState = "approved"
	AccessRequestRejected AccessRequestState = "rejected"
)

type AccessRequest struct {
	ID             string             `json:"id"`
	Username       string             `json:"username"`
	UsernameKey    string             `json:"-"`
	Email          string             `json:"email"`
	EmailKey       string             `json:"-"`
	DisplayName    string             `json:"display_name,omitempty"`
	Reason         string             `json:"reason,omitempty"`
	State          AccessRequestState `json:"state"`
	RequestedAt    time.Time          `json:"requested_at"`
	DecidedAt      *time.Time         `json:"decided_at,omitempty"`
	DecidedBy      string             `json:"decided_by,omitempty"`
	DecisionNote   string             `json:"decision_note,omitempty"`
	ApprovedUserID string             `json:"approved_user_id,omitempty"`
}

// MutationContext is safe request metadata attached to audit events.
type MutationContext struct {
	ActorID   string
	IPAddress string
	UserAgent string
	RequestID string
}
