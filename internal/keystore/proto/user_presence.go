package proto

type UserPresenceCapabilitiesRequest struct{}

type UserPresenceCapabilitiesResponseData struct {
	Available       bool   `json:"available"`
	ShowRecoveryKey bool   `json:"show_recovery_key"`
	Backend         string `json:"backend"`
}
