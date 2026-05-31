package geo

import (
	"os"
	"testing"
)

// These tests run only when real .dat samples are present (dev/testdata, gitignored).
func TestParseRealGeoSite(t *testing.T) {
	data, err := os.ReadFile("../../dev/testdata/geosite.dat")
	if err != nil {
		t.Skip("no geosite.dat sample")
	}
	m := ParseGeoSite(data)
	if len(m) == 0 {
		t.Fatal("no categories parsed")
	}
	if len(m["google"]) == 0 {
		t.Errorf("google category is empty")
	}
	t.Logf("geosite: %d categories; google=%d telegram=%d youtube=%d",
		len(m), len(m["google"]), len(m["telegram"]), len(m["youtube"]))
}

func TestParseRealGeoIP(t *testing.T) {
	data, err := os.ReadFile("../../dev/testdata/geoip.dat")
	if err != nil {
		t.Skip("no geoip.dat sample")
	}
	m := ParseGeoIP(data)
	if len(m) == 0 {
		t.Fatal("no categories parsed")
	}
	var sample string
	if len(m["cn"]) > 0 {
		sample = m["cn"][0]
	}
	if len(m["cn"]) == 0 && len(m["google"]) == 0 && len(m["private"]) == 0 {
		t.Errorf("expected entries in a common category")
	}
	t.Logf("geoip: %d categories; cn=%d google=%d private=%d sample=%q",
		len(m), len(m["cn"]), len(m["google"]), len(m["private"]), sample)
}
