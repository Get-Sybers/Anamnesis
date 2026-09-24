package symbols

import (
	"encoding/binary"
	"testing"
)

var procTag = [4]byte{'P', 'r', 'o', 'c'}

func TestPoolTagMatch(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"exact", []byte("Proc"), true},
		{"protected bit set", []byte{'P', 'r', 'o', 'c' | 0x80}, true},
		{"wrong tag", []byte("Thre"), false},
		{"prefix only", []byte("Prod"), false},
		{"short buffer", []byte("Pro"), false},
	}
	for _, c := range cases {
		if got := PoolTagMatch(c.b, procTag); got != c.want {
			t.Errorf("%s: PoolTagMatch=%v, want %v", c.name, got, c.want)
		}
	}
	// The mask applies to the wanted tag too.
	if !PoolTagMatch([]byte("Proc"), [4]byte{'P', 'r', 'o', 'c' | 0x80}) {
		t.Error("protected bit in the wanted tag must be masked")
	}
}

// header writes a Proc pool header at a chunk-aligned offset.
func header(buf []byte, off int, tag []byte) {
	binary.LittleEndian.PutUint32(buf[off:], 0x04020001) // arbitrary bitfields
	copy(buf[off+4:], tag)
}

func TestScanPoolTag(t *testing.T) {
	buf := make([]byte, 0x400)
	header(buf, 0x040, []byte("Proc"))
	header(buf, 0x100, []byte{'P', 'r', 'o', 'c' | 0x80}) // protected
	header(buf, 0x200, []byte("Thre"))                    // different tag
	copy(buf[0x151:], "Process")                          // text decoy, unaligned
	copy(buf[0x300:], "Proc")                             // aligned but at +0, not a tag position
	header(buf, 0x3f0, []byte("Proc"))                    // last possible chunk

	got := ScanPoolTag(buf, procTag)
	want := []int{0x040, 0x100, 0x3f0}
	if len(got) != len(want) {
		t.Fatalf("hits=%#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hits=%#v, want %#v", got, want)
		}
	}
}

func TestScanPoolTagTruncatedTail(t *testing.T) {
	// Tag bytes begin in-buffer but the 4th byte is cut off: no hit, no panic.
	buf := make([]byte, 0x17)
	copy(buf[0x14:], "Pro")
	if got := ScanPoolTag(buf, procTag); len(got) != 0 {
		t.Fatalf("hits=%#v, want none", got)
	}
}

func TestPoolBackScanDelta(t *testing.T) {
	const endVA = 0x1000
	window := make([]byte, 0x200) // covers [0xe00, 0x1000)
	header(window, 0x1a0, []byte("Proc"))
	d, ok := PoolBackScanDelta(window, endVA, procTag)
	if !ok || d != 0x60 {
		t.Fatalf("delta=%#x ok=%v, want 0x60 true", d, ok)
	}
	// Two headers: the nearest (largest offset) wins.
	header(window, 0x1e0, []byte{'P', 'r', 'o', 'c' | 0x80})
	d, ok = PoolBackScanDelta(window, endVA, procTag)
	if !ok || d != 0x20 {
		t.Fatalf("delta=%#x ok=%v, want 0x20 true", d, ok)
	}
}

func TestPoolBackScanDeltaMisses(t *testing.T) {
	if _, ok := PoolBackScanDelta(make([]byte, 0x100), 0x1000, procTag); ok {
		t.Error("empty window must not match")
	}
	// endVA smaller than the window would place its start before VA 0: the
	// subtraction must fail closed instead of wrapping.
	under := make([]byte, 0x200)
	header(under, 0x1e0, []byte("Proc"))
	if _, ok := PoolBackScanDelta(under, 0x100, procTag); ok {
		t.Error("endVA < len(window) must fail closed, not wrap")
	}
	if _, ok := PoolBackScanDelta(nil, 0x1000, procTag); ok {
		t.Error("nil window must fail closed")
	}
	// A header that would need bytes past the window end is out of reach.
	window := make([]byte, 0x20)
	copy(window[0x18:], "Proc") // tag at +0x14 of a header starting at 0x10... not aligned as tag
	if _, ok := PoolBackScanDelta(window, 0x1000, procTag); ok {
		t.Error("unaligned tag must not match")
	}
}

func TestPoolBackScanDeltaUnalignedStart(t *testing.T) {
	// endVA aligned, window length not a multiple of the chunk size: the scan
	// must still test only chunk-aligned VAs.
	const endVA = 0x1000
	window := make([]byte, 0x1f8) // starts at 0xe08, first aligned VA 0xe10
	// Header at VA 0xf90 = window offset 0x188.
	header(window, 0x188, []byte("Proc"))
	d, ok := PoolBackScanDelta(window, endVA, procTag)
	if !ok || d != 0x70 {
		t.Fatalf("delta=%#x ok=%v, want 0x70 true", d, ok)
	}
}

func TestPlanPoolSweepMergesAndCovers(t *testing.T) {
	vas := []uint64{0x1000_0000, 0x1000_2000, 0x9000_0000}
	ranges, truncated := PlanPoolSweep(vas, 0x1000, 0x10000, 1<<40)
	if truncated {
		t.Fatal("unexpected truncation")
	}
	if len(ranges) != 2 {
		t.Fatalf("ranges=%#v, want 2 merged ranges", ranges)
	}
	for _, va := range vas {
		covered := false
		for _, r := range ranges {
			if va >= r.Start && va < r.End {
				covered = true
			}
		}
		if !covered {
			t.Errorf("va %#x not covered by %#v", va, ranges)
		}
	}
	for i := 1; i < len(ranges); i++ {
		if ranges[i].Start <= ranges[i-1].End {
			t.Errorf("ranges overlap or are unsorted: %#v", ranges)
		}
	}
}

func TestPlanPoolSweepShrinksToCap(t *testing.T) {
	// Two far-apart addresses with a huge margin: the plan must self-shrink
	// under the cap without dropping coverage.
	vas := []uint64{0x1000_0000, 0x9000_0000}
	ranges, truncated := PlanPoolSweep(vas, 1<<30, 1<<20, 1<<24)
	if truncated {
		t.Fatal("shrinking should have avoided truncation")
	}
	var total uint64
	for _, r := range ranges {
		total += r.End - r.Start
	}
	if total > 1<<24 {
		t.Fatalf("total %#x exceeds cap", total)
	}
	for _, va := range vas {
		covered := false
		for _, r := range ranges {
			if va >= r.Start && va < r.End {
				covered = true
			}
		}
		if !covered {
			t.Errorf("va %#x lost by shrinking", va)
		}
	}
}

func TestPlanPoolSweepEmpty(t *testing.T) {
	if ranges, truncated := PlanPoolSweep(nil, 1, 1, 1); ranges != nil || truncated {
		t.Fatalf("empty input: got %#v %v", ranges, truncated)
	}
}

func TestPlanPoolSweepUnderflowClamp(t *testing.T) {
	ranges, _ := PlanPoolSweep([]uint64{0x100}, 0x1000, 0, 1<<20)
	if len(ranges) != 1 || ranges[0].Start != 0 {
		t.Fatalf("underflowed start must clamp to 0: %#v", ranges)
	}
}

func TestSubtractRanges(t *testing.T) {
	a := []VARange{{0x100, 0x500}, {0x800, 0x900}, {0xa00, 0xb00}}
	b := []VARange{{0x0, 0x150}, {0x200, 0x300}, {0x480, 0x850}, {0xa00, 0xb00}}
	got := SubtractRanges(a, b)
	want := []VARange{{0x150, 0x200}, {0x300, 0x480}, {0x850, 0x900}}
	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
	if r := SubtractRanges(a, nil); len(r) != len(a) {
		t.Fatalf("subtracting nothing must keep a: %#v", r)
	}
	if r := SubtractRanges(nil, b); r != nil {
		t.Fatalf("empty a must stay empty: %#v", r)
	}
	if r := SubtractRanges(a, a); r != nil {
		t.Fatalf("a-a must be empty: %#v", r)
	}
}
