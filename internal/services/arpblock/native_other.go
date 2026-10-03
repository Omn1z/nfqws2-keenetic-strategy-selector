//go:build !linux

package arpblock

func nativeBackend() (string, string, commandFunc) {
	return "unsupported", "Управление изоляцией доступно на роутере Keenetic", nil
}
