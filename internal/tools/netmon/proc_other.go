//go:build !linux

package netmon

// Non-Linux stubs so the project builds and tests on the dev box. The real /proc
// readers live in proc_linux.go.

func Conntrack() ([]Conn, error)    { return nil, ErrUnsupported }
func Count() (int, int, error)      { return 0, 0, ErrUnsupported }
func Queues() ([]QueueStat, error)  { return nil, ErrUnsupported }
func ARP() ([]ARPEntry, error)      { return nil, ErrUnsupported }
func Ifaces() ([]IfaceBytes, error) { return nil, ErrUnsupported }
