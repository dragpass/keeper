package service

import (
	"strings"
	"testing"
)

func TestSystemdUnitEscapesExecutableAndRunsInUserSession(t *testing.T) {
	unit := renderSystemdUnit("/home/test/My $HOME/100%/DragPass Keeper/dragpass-keeper", "/home/test/DragPass trust.json")
	for _, expected := range []string{
		`ExecStart="/home/test/My $$HOME/100%%/DragPass Keeper/dragpass-keeper" --app-service`,
		`Environment="DRAGPASS_KEY_TRANSPARENCY_TRUST_FILE=/home/test/DragPass trust.json"`,
		"After=graphical-session.target", "Restart=on-failure", "WantedBy=default.target",
	} {
		if !strings.Contains(unit, expected) {
			t.Errorf("systemd unit does not contain %q", expected)
		}
	}
}
