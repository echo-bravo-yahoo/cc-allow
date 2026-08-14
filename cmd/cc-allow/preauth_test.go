package main

import (
	"testing"
)

// configFromTOMLAt parses a config and stamps it with a path, so merged rules
// carry a source the way LoadConfigWithDefaults would.
func configFromTOMLAt(t *testing.T, path, toml string) *Config {
	t.Helper()
	cfg := configFromTOML(t, toml)
	cfg.Path = path
	return cfg
}

// TestMergeShadowsEqualPatternAllow covers the trap a session grant hits first:
// an allow rule whose pattern is identical to an existing deny is dropped before
// specificity scoring, so it never takes effect.
func TestMergeShadowsEqualPatternAllow(t *testing.T) {
	global := configFromTOMLAt(t, "/global/cc-allow.toml", `
version = "2.0"
[bash]
default = "ask"

[[bash.deny.op.read]]
message = "Use cc-cred run instead"
`)

	session := configFromTOMLAt(t, "/session/abc.toml", `
version = "2.0"

[[bash.allow.op.read]]
`)

	merged := MergeConfigs([]*Config{global, session})

	var allow *TrackedRule[BashRule]
	for i := range merged.Rules {
		if merged.Rules[i].Rule.Action == ActionAllow {
			allow = &merged.Rules[i]
		}
	}
	if allow == nil {
		t.Fatal("expected the session allow rule in the merged rules")
	}
	if !allow.Shadowed {
		t.Error("bare session allow should be shadowed by the identical global deny")
	}
	if allow.ShadowedBy != "/global/cc-allow.toml" {
		t.Errorf("ShadowedBy = %q, want the global config path", allow.ShadowedBy)
	}

	// The deny keeps competing: it is not the one that got dropped.
	for _, tr := range merged.Rules {
		if tr.Rule.Action == ActionDeny && tr.Shadowed {
			t.Error("the stricter deny should not be shadowed by a weaker allow")
		}
	}
}

// TestMergeArgsConditionBreaksShadowing is the escape hatch: adding an args
// condition makes the allow a different pattern, so it competes and outscores.
func TestMergeArgsConditionBreaksShadowing(t *testing.T) {
	global := configFromTOMLAt(t, "/global/cc-allow.toml", `
version = "2.0"
[bash]
default = "ask"

[[bash.deny.op.read]]
message = "Use cc-cred run instead"
`)

	session := configFromTOMLAt(t, "/session/abc.toml", `
version = "2.0"

[[bash.allow.op.read]]
args.any = ["re:^op://Automation/"]
`)

	merged := MergeConfigs([]*Config{global, session})

	for _, tr := range merged.Rules {
		if tr.Shadowed {
			t.Errorf("no rule should be shadowed, but %q action=%s from %s was (by %s)",
				tr.Rule.Command, tr.Rule.Action, tr.Source, tr.ShadowedBy)
		}
	}
}

// TestMergeShadowingIsRecordedBothWays checks the reverse direction: a later
// stricter rule displaces an earlier looser one, and both ends are named.
func TestMergeShadowingIsRecordedBothWays(t *testing.T) {
	first := configFromTOMLAt(t, "/first.toml", `
version = "2.0"

[[bash.allow.curl]]
`)

	second := configFromTOMLAt(t, "/second.toml", `
version = "2.0"

[[bash.deny.curl]]
message = "no"
`)

	merged := MergeConfigs([]*Config{first, second})

	var allow, deny *TrackedRule[BashRule]
	for i := range merged.Rules {
		switch merged.Rules[i].Rule.Action {
		case ActionAllow:
			allow = &merged.Rules[i]
		case ActionDeny:
			deny = &merged.Rules[i]
		}
	}
	if allow == nil || deny == nil {
		t.Fatal("expected both rules in the merged rules")
	}
	if !allow.Shadowed {
		t.Error("the earlier allow should be shadowed by the later deny")
	}
	if allow.ShadowedBy != "/second.toml" {
		t.Errorf("allow.ShadowedBy = %q, want /second.toml", allow.ShadowedBy)
	}
	if deny.Shadowing != "/first.toml" {
		t.Errorf("deny.Shadowing = %q, want /first.toml", deny.Shadowing)
	}
	if deny.Shadowed {
		t.Error("the winning deny should not itself be marked shadowed")
	}
}

// preauthGlobalConfig mirrors the shape of the real global config for the four
// obstacles a session grant has to clear: a bare default ask, an explicit deny
// table rule, and a flat bash.deny.commands entry.
const preauthGlobalConfig = `
version = "2.0"
[bash]
default = "ask"
unresolved_commands = "ask"
respect_file_rules = false

[bash.deny]
commands = ["sudo"]
message = "sudo is never allowed"

[[bash.deny.op.item.get]]
message = "Use cc-cred run instead of printing a secret"
`

// TestPreauthSessionGrants reproduces each row of the pre-auth verification
// table over a two-config chain, including the negative case that proves the
// grant did not widen past what was asked for.
func TestPreauthSessionGrants(t *testing.T) {
	tests := []struct {
		name      string
		session   string
		positive  string
		wantPos   Action
		negative  string
		wantNeg   Action
		posReason string
		negReason string
	}{
		{
			name: "subcommand allow beats the default ask",
			session: `
version = "2.0"

[[bash.allow.npm.install]]
`,
			positive:  "npm install",
			wantPos:   ActionAllow,
			negative:  "npm publish",
			wantNeg:   ActionAsk,
			posReason: "npm install was granted",
			negReason: "the grant covers only the install subcommand",
		},
		{
			name: "positional arg pins the allow to one host",
			session: `
version = "2.0"

[[bash.allow.ssh]]
args.position = { "0" = "stockholm" }
`,
			positive:  "ssh stockholm uptime",
			wantPos:   ActionAllow,
			negative:  "ssh other-host uptime",
			wantNeg:   ActionAsk,
			posReason: "ssh to the named host was granted",
			negReason: "the grant covers only the named host",
		},
		{
			name: "args condition outscores an explicit deny",
			session: `
version = "2.0"

[[bash.allow.op.item.get]]
args.any = ["re:^op://Automation/"]
`,
			positive:  "op item get op://Automation/syncthing/password",
			wantPos:   ActionAllow,
			negative:  "op item get op://Personal/bank/password",
			wantNeg:   ActionDeny,
			posReason: "the vault-scoped override applies",
			negReason: "the global deny still governs every other vault",
		},
		{
			name: "flat deny.commands cannot be pre-authorized",
			session: `
version = "2.0"

[bash.allow]
commands = ["sudo"]

[[bash.allow.sudo]]
args.any = ["apt-cache"]
`,
			positive:  "sudo apt-cache search foo",
			wantPos:   ActionDeny,
			negative:  "sudo rm -rf /",
			wantNeg:   ActionDeny,
			posReason: "a flat deny is checked before any table rule and no later config can lift it",
			negReason: "the flat deny is unchanged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			global := configFromTOMLAt(t, "/global/cc-allow.toml", preauthGlobalConfig)
			session := configFromTOMLAt(t, "/session/abc.toml", tt.session)
			chain := []*Config{global, session}

			if r := parseAndEvalChain(t, chain, tt.positive); r.Action != tt.wantPos {
				t.Errorf("%q = %s, want %s (%s)", tt.positive, r.Action, tt.wantPos, tt.posReason)
			}
			if r := parseAndEvalChain(t, chain, tt.negative); r.Action != tt.wantNeg {
				t.Errorf("%q = %s, want %s (%s)", tt.negative, r.Action, tt.wantNeg, tt.negReason)
			}
		})
	}
}

// TestPreauthBareAllowStaysDenied is the same chain without an args condition:
// the grant is written, the merge drops it, and the decision does not move.
func TestPreauthBareAllowStaysDenied(t *testing.T) {
	global := configFromTOMLAt(t, "/global/cc-allow.toml", preauthGlobalConfig)
	session := configFromTOMLAt(t, "/session/abc.toml", `
version = "2.0"

[[bash.allow.op.item.get]]
`)

	r := parseAndEvalChain(t, []*Config{global, session}, "op item get op://Automation/syncthing/password")
	if r.Action != ActionDeny {
		t.Errorf("bare allow = %s, want deny: an equal-pattern allow is shadowed before scoring", r.Action)
	}
}

func TestResolveSessionID(t *testing.T) {
	tests := []struct {
		name    string
		flagVal string
		hookVal string
		env     string
		want    string
	}{
		{name: "hook wins over flag and env", flagVal: "flag-id", hookVal: "hook-id", env: "env-id", want: "hook-id"},
		{name: "flag wins over env", flagVal: "flag-id", env: "env-id", want: "flag-id"},
		{name: "env is the fallback", env: "env-id", want: "env-id"},
		{name: "empty when nothing is set", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CLAUDE_CODE_SESSION_ID", tt.env)
			if got := resolveSessionID(tt.flagVal, tt.hookVal); got != tt.want {
				t.Errorf("resolveSessionID(%q, %q) with env %q = %q, want %q",
					tt.flagVal, tt.hookVal, tt.env, got, tt.want)
			}
		})
	}
}
