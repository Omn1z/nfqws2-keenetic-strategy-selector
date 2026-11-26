//go:build !linux

package probe

// setReuse is a no-op on non-Linux hosts (the production target is Linux; this
// keeps the package buildable on the dev machine).
func setReuse(fd uintptr) {}
