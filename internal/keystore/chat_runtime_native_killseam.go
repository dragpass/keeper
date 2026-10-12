//go:build keeper_killseam

package keystore

// nativeFramesDriveChat lets the kill harness (killharness/, a keeper_killseam
// build that is never released) drive chat over Native Messaging framing on
// the release entry point, under the lease rules Native Messaging had before
// chat became App-only. The App-only refusal itself is tested in the default
// build (chat_runtime_test.go, localrpc process tests).
const nativeFramesDriveChat = true
