package portforward

const (
	sourceActivision = "Activision Support: Ports Used for Call of Duty Games, updated 2026-02-03"
	sourceDeltaForce = "PortForward: Delta Force PC"
)

var (
	codCurrentProfiles = []Profile{
		{
			ID:   "steam",
			Name: "Steam",
			TCP:  ranges(3074, 27015, 27036),
			UDP:  ranges(3074, 27015, rng(27031, 27036)),
		},
		{
			ID:   "pc",
			Name: "PC",
			TCP:  ranges(3074, 4000, rng(6112, 6119), 20500, 20510, rng(27014, 27050), 28960),
			UDP:  ranges(3074, 3478, rng(4379, 4380), rng(6112, 6119), 20500, 20510, rng(27000, 27031), 27036, 28960),
		},
		{
			ID:   "playstation",
			Name: "PlayStation",
			TCP:  ranges(rng(3478, 3480)),
			UDP:  ranges(3074, rng(3478, 3479)),
		},
		{
			ID:   "xbox",
			Name: "Xbox",
			TCP:  ranges(3074),
			UDP:  ranges(88, 500, 3074, 3544, 4500),
		},
	}

	codVanguardProfiles = []Profile{
		{
			ID:   "pc",
			Name: "PC",
			TCP:  ranges(3074, rng(27014, 27050)),
			UDP:  ranges(rng(3074, 3079)),
		},
		{
			ID:   "playstation",
			Name: "PlayStation",
			TCP:  ranges(1935, rng(3478, 3480)),
			UDP:  ranges(rng(3074, 3079), rng(3478, 3479)),
		},
		{
			ID:   "xbox",
			Name: "Xbox",
			TCP:  ranges(3074),
			UDP:  ranges(88, 500, rng(3074, 3079), 3544, 4500),
		},
	}

	codMW2019Profiles = []Profile{
		{
			ID:   "pc",
			Name: "PC",
			TCP:  ranges(3074, rng(27014, 27050)),
			UDP:  ranges(3074, 3478, rng(4379, 4380), rng(27000, 27031), 27036),
		},
		{
			ID:   "playstation",
			Name: "PlayStation",
			TCP:  ranges(1935, rng(3478, 3480)),
			UDP:  ranges(3074, rng(3478, 3479)),
		},
		{
			ID:   "xbox",
			Name: "Xbox",
			TCP:  ranges(3074),
			UDP:  ranges(88, 500, 3074, 3075, 3544, 4500),
		},
	}

	presets = []Preset{
		{ID: "cod-bo7", Name: "Call Of Duty Black Ops 7", Source: sourceActivision, Profiles: codCurrentProfiles},
		{ID: "cod-bo6", Name: "Call Of Duty Black Ops 6", Source: sourceActivision, Profiles: codCurrentProfiles},
		{ID: "cod-mw-2023", Name: "Call Of Duty Modern Warfare 2023", Source: sourceActivision, Profiles: codCurrentProfiles},
		{ID: "cod-mw-2022", Name: "Call Of Duty Modern Warfare 2022", Source: sourceActivision, Profiles: codCurrentProfiles},
		{ID: "cod-mw-2019", Name: "Call Of Duty Modern Warfare 2019", Source: sourceActivision, Profiles: codMW2019Profiles},
		{ID: "cod-vanguard", Name: "Call Of Duty Vanguard", Source: sourceActivision, Profiles: codVanguardProfiles},
		{ID: "delta-force", Name: "Delta Force", Source: sourceDeltaForce, Profiles: []Profile{
			{ID: "pc", Name: "PC", UDP: ranges(rng(3568, 3569))},
		}},
	}
)

func rng(start, end int) Range { return Range{Start: start, End: end} }

func ranges(values ...any) []Range {
	out := make([]Range, 0, len(values))
	for _, v := range values {
		switch x := v.(type) {
		case int:
			out = append(out, Range{Start: x, End: x})
		case Range:
			out = append(out, x)
		}
	}
	return out
}

// Presets returns a deep copy of all built-in presets.
func Presets() []Preset {
	out := make([]Preset, len(presets))
	for i := range presets {
		out[i] = clonePreset(presets[i])
	}
	return out
}

func findPresetProfile(presetID, profileID string) (Preset, Profile, bool) {
	for _, p := range presets {
		if p.ID != presetID {
			continue
		}
		for _, prof := range p.Profiles {
			if prof.ID == profileID {
				return clonePreset(p), cloneProfile(prof), true
			}
		}
		return clonePreset(p), Profile{}, false
	}
	return Preset{}, Profile{}, false
}

func clonePreset(p Preset) Preset {
	p.Profiles = cloneProfiles(p.Profiles)
	return p
}

func cloneProfiles(in []Profile) []Profile {
	out := make([]Profile, len(in))
	for i := range in {
		out[i] = cloneProfile(in[i])
	}
	return out
}

func cloneProfile(p Profile) Profile {
	p.TCP = cloneRanges(p.TCP)
	p.UDP = cloneRanges(p.UDP)
	return p
}

func cloneRanges(in []Range) []Range {
	if len(in) == 0 {
		return []Range{}
	}
	out := make([]Range, len(in))
	copy(out, in)
	return out
}
