//go:build windows

package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/dragpass/keeper/internal/keystore/localrpc"
)

func TestWindowsScheduledKeeperServiceStartsAndServesHealth(t *testing.T) {
	executable := os.Getenv("KEEPER_WINDOWS_SERVICE_TEST_BINARY")
	if executable == "" {
		t.Skip("set KEEPER_WINDOWS_SERVICE_TEST_BINARY to run the Task Scheduler integration test")
	}

	taskName := fmt.Sprintf("%s integration-%d", scheduledTaskName, time.Now().UnixNano())
	if err := manageWindowsTask("install", executable, taskName); err != nil {
		t.Fatalf("install and start test Keeper task: %v", err)
	}
	t.Cleanup(func() {
		if err := manageWindowsTask("uninstall", executable, taskName); err != nil {
			t.Errorf("remove test Keeper task: %v", err)
		}
	})

	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		request, err := http.NewRequest(http.MethodGet, "http://"+localrpc.DefaultAddress+"/v1/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", "https://app.dragpass.io")
		request.Header.Set("X-DragPass-Local-RPC", "1")
		request.Header.Set("Sec-Fetch-Site", "same-site")

		response, err := client.Do(request)
		if err == nil {
			var health struct {
				Version string `json:"version"`
				Hash    string `json:"hash"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&health)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil && health.Version != "" {
				return
			}
			lastErr = fmt.Errorf("health response status=%d version=%q decode=%v", response.StatusCode, health.Version, decodeErr)
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("scheduled Keeper did not serve health before timeout: %v", lastErr)
}
