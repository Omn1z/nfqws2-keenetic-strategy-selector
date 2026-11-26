package arpspoof

// Vendors returns a compact set of common router/Wi-Fi vendors. Prefixes are
// written as 24-bit OUI values; the UI/backend can also accept shorter byte
// prefixes and manual full MAC addresses.
func Vendors() []Vendor {
	return []Vendor{
		{ID: "iskratel", Name: "Iskratel", Prefixes: []string{"64:6E:EA"}},
		{ID: "rostelecom", Name: "Rostelecom CPE", Prefixes: []string{"F8:8C:21", "D8:D7:75", "E8:65:D4"}},
		{ID: "zyxel", Name: "Zyxel", Prefixes: []string{"00:13:49", "00:19:CB", "FC:F5:28"}},
		{ID: "huawei", Name: "Huawei", Prefixes: []string{"00:18:82", "00:1E:10", "28:6E:D4", "A4:C6:4F"}},
		{ID: "asus", Name: "ASUS", Prefixes: []string{"00:1B:FC", "04:92:26", "2C:56:DC", "AC:22:0B"}},
		{ID: "xiaomi", Name: "Xiaomi", Prefixes: []string{"50:8F:4C", "64:09:80", "74:23:44", "D4:97:0B"}},
		{ID: "tp-link", Name: "TP-Link", Prefixes: []string{"14:CC:20", "50:C7:BF", "98:DA:C4", "C0:25:E9"}},
		{ID: "d-link", Name: "D-Link", Prefixes: []string{"00:05:5D", "1C:7E:E5", "84:C9:B2", "C4:A8:1D"}},
		{ID: "zte", Name: "ZTE", Prefixes: []string{"00:19:C6", "34:4B:50", "E8:BD:D1"}},
		{ID: "sagemcom", Name: "Sagemcom", Prefixes: []string{"00:1D:19", "60:35:C0", "A0:1B:29"}},
		{ID: "sercomm", Name: "Sercomm", Prefixes: []string{"00:1D:AA", "20:0C:C8", "7C:03:D8"}},
		{ID: "netgear", Name: "NETGEAR", Prefixes: []string{"00:14:6C", "20:4E:7F", "A0:40:A0"}},
		{ID: "custom", Name: "Custom", Prefixes: []string{}},
	}
}

func firstVendorPrefix(id string) string {
	for _, v := range Vendors() {
		if v.ID == id && len(v.Prefixes) > 0 {
			return v.Prefixes[0]
		}
	}
	return ""
}

func vendorHasPrefix(id, prefix string) bool {
	for _, v := range Vendors() {
		if v.ID != id {
			continue
		}
		for _, p := range v.Prefixes {
			if p == prefix {
				return true
			}
		}
	}
	return false
}
