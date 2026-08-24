package config

import (
	"testing"
)

func TestDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9443" || c.DockerSocket != "/var/run/docker.sock" {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if c.AllowWrite {
		t.Error("write tier must be off unless asked for")
	}
	if !c.TokenGenerated || c.Token == "" {
		t.Error("an absent token must be generated, not left empty")
	}
}

func TestGeneratedTokensDiffer(t *testing.T) {
	a, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if a.Token == b.Token {
		t.Fatal("generated tokens are not random")
	}
	if len(a.Token) < 32 {
		t.Errorf("token %q is too short to be worth generating", a.Token)
	}
}

func TestExplicitTokenIsNotFlaggedGenerated(t *testing.T) {
	t.Setenv("CAPSTAN_TOKEN", "supplied")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "supplied" || c.TokenGenerated {
		t.Errorf("token=%q generated=%v", c.Token, c.TokenGenerated)
	}
}

// A typo must leave writes off. Silently reading "yes!" as consent is how a
// read-only deployment quietly becomes a writable one.
func TestAllowWriteOnlyAcceptsClearAffirmatives(t *testing.T) {
	on := []string{"1", "true", "TRUE", "True", "yes", "on", " true "}
	for _, v := range on {
		t.Setenv("CAPSTAN_ALLOW_WRITE", v)
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if !c.AllowWrite {
			t.Errorf("%q: writes off, want on", v)
		}
	}
	off := []string{"", "0", "false", "no", "off", "yes!", "y", "enable", "maybe", "2"}
	for _, v := range off {
		t.Setenv("CAPSTAN_ALLOW_WRITE", v)
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.AllowWrite {
			t.Errorf("%q: writes on, want off", v)
		}
	}
}

func TestExtraSANsParsing(t *testing.T) {
	t.Setenv("CAPSTAN_TLS_SANS", " docker-01.lan , 10.0.0.7 ,, ")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ExtraSANs) != 2 || c.ExtraSANs[0] != "docker-01.lan" || c.ExtraSANs[1] != "10.0.0.7" {
		t.Errorf("ExtraSANs = %q", c.ExtraSANs)
	}
}
