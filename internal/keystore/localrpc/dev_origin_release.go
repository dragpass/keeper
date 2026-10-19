//go:build !keeper_e2e

package localrpc

// A release build trusts no development App origin; dev_origin_e2e.go holds
// the opt-in.
func devAppOrigin(func(string) string) string { return "" }
