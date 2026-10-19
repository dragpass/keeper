//go:build keeper_e2e

package localrpc

import "strings"

// DevAppOriginEnvVar opts one development App origin in. It exists only in a
// keeper_e2e build, which the browser E2E harness runs against a local App
// dev server; a release build refuses to start when it is set (main).
const DevAppOriginEnvVar = "DRAGPASS_KEEPER_DEV_APP_ORIGIN"

func devAppOrigin(getenv func(string) string) string {
	return strings.TrimSpace(getenv(DevAppOriginEnvVar))
}
