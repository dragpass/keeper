// Package killharness holds the real-process kill tests of the chat state: the
// Keeper binary itself, built with the MLS library and the keeper_killseam
// tag, driven over Native Messaging and killed with SIGKILL at the named
// points chatstate/crashpoint.go defines. It has no code outside its tests.
package killharness
