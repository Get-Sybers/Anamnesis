package collect

import "testing"

func TestSplitRegistryPath(t *testing.T) {
	cases := []struct {
		in, hive, key string
	}{
		{`\[ffffd88bfd0e2000:80000218] SYSTEM\ControlSet001\Control\hivelist`, "SYSTEM", `ControlSet001\Control\hivelist`},
		{`[ffffd88bfd05a000:00000020] ROOT`, "ROOT", ""},
		{`[ffffd88bfd05a000:00000168] \MACHINE`, "MACHINE", ""},
		{`\[ffffd88bfdb3a000:01ec0330] SOFTWARE\Microsoft\Windows`, "SOFTWARE", `Microsoft\Windows`},
		{`\REGISTRY\MACHINE\SOFTWARE\Classes`, "HKLM", `SOFTWARE\Classes`},
		{`\REGISTRY\MACHINE`, "HKLM", ""},
		{`\REGISTRY\USER`, "HKU", ""},
		{`\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\Vendor`, `HKU\S-1-5-21-1-2-3-1001`, `Software\Vendor`},
		{`\REGISTRY\USER\S-1-5-18`, `HKU\S-1-5-18`, ""},
	}
	for _, c := range cases {
		hive, key := splitRegistryPath(c.in)
		if hive != c.hive || key != c.key {
			t.Errorf("splitRegistryPath(%q) = (%q, %q), want (%q, %q)", c.in, hive, key, c.hive, c.key)
		}
	}
}
