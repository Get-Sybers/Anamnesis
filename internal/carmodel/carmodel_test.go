package carmodel

import "testing"

// Port of test_car_pipeline.py::test_model_is_authoritative_13_objects.
func TestModelIsAuthoritative13Objects(t *testing.T) {
	m := Load()
	if len(m.Names) != 13 {
		t.Fatalf("want 13 objects, got %d: %v", len(m.Names), m.Names)
	}
	for _, o := range []string{"authentication", "email", "http", "socket"} {
		if _, ok := m.Objs[o]; !ok {
			t.Errorf("missing object %q", o)
		}
	}
	pf := FieldSet("process")
	for _, f := range []string{"guid", "parent_guid", "target_guid"} {
		if !pf[f] {
			t.Errorf("process missing field %q", f)
		}
	}
	all := map[string]bool{}
	for _, f := range AllFields() {
		all[f] = true
	}
	for _, f := range Fields("flow") {
		if !all[f] {
			t.Errorf("AllFields missing flow field %q", f)
		}
	}
}
