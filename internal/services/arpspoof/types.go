// Package arpspoof owns router-side ARP reply MAC rewriting.
package arpspoof

// Vendor is a selectable MAC/OUI prefix group shown in the UI.
type Vendor struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Prefixes []string `json:"prefixes"`
}

// Config is the persisted ARP spoofing configuration.
type Config struct {
	Enabled   bool     `json:"enabled"`
	MAC       string   `json:"mac"`
	VendorID  string   `json:"vendor_id"`
	Prefix    string   `json:"prefix"`
	Ifaces    []string `json:"ifaces"`
	UpdatedAt int64    `json:"updated_at"`
}

// Interface is an available router interface candidate.
type Interface struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	Up        bool   `json:"up"`
	Suggested bool   `json:"suggested"`
}

// Tools reports whether the router has the required L2 firewall tools.
type Tools struct {
	IP        bool `json:"ip"`
	Arptables bool `json:"arptables"`
	Ebtables  bool `json:"ebtables"`
}

// View is returned to the UI.
type View struct {
	Config          Config      `json:"config"`
	Vendors         []Vendor    `json:"vendors"`
	Ifaces          []Interface `json:"ifaces"`
	SuggestedIfaces []string    `json:"suggested_ifaces"`
	HookPath        string      `json:"hook_path"`
	Tools           Tools       `json:"tools"`
	Active          bool        `json:"active"`
	LastError       string      `json:"last_error"`
	AppliedAt       int64       `json:"applied_at"`
}

type state struct {
	Config       Config            `json:"config"`
	LastError    string            `json:"last_error"`
	AppliedAt    int64             `json:"applied_at"`
	OriginalMACs map[string]string `json:"original_macs,omitempty"`
}
