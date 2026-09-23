//go:build mls && cgo

package mls

// OpenSessionForTest lets the external test package play a client no Keeper
// is: one whose leaf carries no declaration, or one it chose itself. Only a
// _test file can reach it, so no build of the Keeper exports a way to hand a
// group a signer.
var OpenSessionForTest = openSession
