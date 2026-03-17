package policy

// MergePolicySets merges a base policy set with an overlay.
// Overlay values take precedence. Policies are concatenated (overlay after base).
// Roles are merged (overlay overwrites base for same role name).
func MergePolicySets(base, overlay *PolicySet) *PolicySet {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}

	merged := &PolicySet{
		Version: overlay.Version,
		Defaults: overlay.Defaults,
		Roles:    make(map[string]Role),
	}

	if merged.Version == "" {
		merged.Version = base.Version
	}
	if merged.Defaults.Action == "" {
		merged.Defaults = base.Defaults
	}

	// Merge roles: base first, overlay overwrites
	for k, v := range base.Roles {
		merged.Roles[k] = v
	}
	for k, v := range overlay.Roles {
		merged.Roles[k] = v
	}

	// Concatenate policies: base first, then overlay
	// This means overlay policies are checked AFTER base (but before defaults)
	// If you want overlay to take priority, reverse the order
	merged.Policies = make([]PolicyRule, 0, len(base.Policies)+len(overlay.Policies))
	merged.Policies = append(merged.Policies, overlay.Policies...) // overlay first = higher priority
	merged.Policies = append(merged.Policies, base.Policies...)

	return merged
}
