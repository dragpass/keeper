package service

import "strings"

func renderSystemdUnit(executable, trustFile string) string {
	unit := "[Unit]\nDescription=DragPass Keeper App service\nAfter=graphical-session.target\n\n" +
		"[Service]\nType=simple\nExecStart=" + quoteSystemdArgument(executable) + " --app-service\n" +
		"Restart=on-failure\nRestartSec=2\n"
	if trustFile != "" {
		unit += "Environment=" + quoteSystemdArgument("DRAGPASS_KEY_TRANSPARENCY_TRUST_FILE="+trustFile) + "\n"
	}
	return unit + "\n[Install]\nWantedBy=default.target\n"
}

func quoteSystemdArgument(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", `"`, `\"`, "\n", `\n`, "\r", `\r`, "$", "$$", "%", "%%")
	return `"` + replacer.Replace(value) + `"`
}
