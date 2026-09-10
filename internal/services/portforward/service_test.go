package portforward

import "testing"

func TestPresetsContainRequestedGames(t *testing.T) {
	want := []string{
		"cod-bo7",
		"cod-bo6",
		"cod-mw-2023",
		"cod-mw-2022",
		"cod-mw-2019",
		"cod-vanguard",
		"delta-force",
	}
	got := map[string]bool{}
	for _, p := range Presets() {
		got[p.ID] = true
		for _, prof := range p.Profiles {
			if err := validateRanges(prof.TCP); err != nil {
				t.Fatalf("%s/%s TCP: %v", p.ID, prof.ID, err)
			}
			if err := validateRanges(prof.UDP); err != nil {
				t.Fatalf("%s/%s UDP: %v", p.ID, prof.ID, err)
			}
		}
	}
	for _, id := range want {
		if !got[id] {
			t.Fatalf("missing preset %s", id)
		}
	}
}

func TestPrepareRuleCopiesPresetPorts(t *testing.T) {
	s := &Service{}
	r, err := s.prepareRule(Rule{
		PresetID:  "cod-bo7",
		ProfileID: "pc",
		DeviceIP:  "192.168.3.25",
		Enabled:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "Call Of Duty Black Ops 7 - PC" {
		t.Fatalf("unexpected name %q", r.Name)
	}
	if len(r.TCP) == 0 || len(r.UDP) == 0 {
		t.Fatalf("ports were not copied: %#v", r)
	}
	if r.DeviceIP != "192.168.3.25" {
		t.Fatalf("unexpected ip %q", r.DeviceIP)
	}
}
