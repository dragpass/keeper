package proto

type UserPresenceCapabilitiesRequest struct{}

type UserPresenceCapabilitiesResponseData struct {
	Available       bool   `json:"available"`
	PromptSecret    bool   `json:"prompt_secret"`
	PromptNewSecret bool   `json:"prompt_new_secret"`
	Confirm         bool   `json:"confirm"`
	ShowRecoveryKey bool   `json:"show_recovery_key"`
	Backend         string `json:"backend"`
}
