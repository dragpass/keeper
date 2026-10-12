//go:build !keeper_killseam

package keystore

// nativeFramesDriveChat is false in every build but the kill harness's:
// a Native Messaging frame never runs an App-only action.
const nativeFramesDriveChat = false
