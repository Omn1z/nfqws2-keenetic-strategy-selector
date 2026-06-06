// Package portforward owns router-side port forwarding presets and rules.
package portforward

// Range is an inclusive TCP/UDP port range.
type Range struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Profile is a platform-specific set of ports inside a game preset.
type Profile struct {
	ID   string  `json:"id"`
	Name string  `json:"name"`
	TCP  []Range `json:"tcp"`
	UDP  []Range `json:"udp"`
}

// Preset is a ready-made game port list.
type Preset struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Source   string    `json:"source"`
	Profiles []Profile `json:"profiles"`
}

// Rule maps a preset profile to a selected LAN device.
type Rule struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	PresetID    string  `json:"preset_id"`
	ProfileID   string  `json:"profile_id"`
	DeviceIP    string  `json:"device_ip"`
	DeviceName  string  `json:"device_name"`
	DeviceMAC   string  `json:"device_mac"`
	DeviceIface string  `json:"device_iface"`
	Enabled     bool    `json:"enabled"`
	TCP         []Range `json:"tcp"`
	UDP         []Range `json:"udp"`
	CreatedAt   int64   `json:"created_at"`
	UpdatedAt   int64   `json:"updated_at"`
}

// View is returned to the UI.
type View struct {
	Presets   []Preset `json:"presets"`
	Rules     []Rule   `json:"rules"`
	WANIfaces []string `json:"wan_ifaces"`
	HookPath  string   `json:"hook_path"`
}

type state struct {
	Rules []Rule `json:"rules"`
}
