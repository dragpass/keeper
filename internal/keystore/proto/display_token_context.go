package proto

// DisplayTokenLegacyRefused is returned when an isolated display request
// carries a drag token whose expiry Keeper cannot authenticate. Existing drag
// tokens (personal, current Group, retained Group and audit) carry no
// authenticated expiry, and a missing E= never means "no expiry".
const DisplayTokenLegacyRefused = "TOKEN_LEGACY_REFUSED"

// DisplayTokenContext is the authenticated metadata of one drag token that an
// authenticated-expiry token format admitted for isolated display. ExpiresAt
// is Unix seconds, or 0 only when the format explicitly authenticates the
// no-expiry state.
type DisplayTokenContext struct {
	Scope      string
	DekVersion int
	OrgID      string
	GroupID    string
	ExpiresAt  int64
}
