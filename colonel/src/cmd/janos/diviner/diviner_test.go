package diviner

import (
	"strings"
	"testing"
)

// TestOpenMissingScheme: URL without :// -> clear error.
func TestOpenMissingScheme(t *testing.T) {
	_, err := Open("no-scheme-here")
	if err == nil || !strings.Contains(err.Error(), "missing scheme") {
		t.Errorf("expected missing-scheme error, got %v", err)
	}
}

// TestOpenFileSchemeRejected: file:// is banned unconditionally.
func TestOpenFileSchemeRejected(t *testing.T) {
	_, err := Open("file:///tmp/leaked.pem")
	if err == nil {
		t.Fatal("Open accepted file:// URL")
	}
	if !strings.Contains(err.Error(), "file://") {
		t.Errorf("error should mention file://: %v", err)
	}
}

// TestOpenUnknownScheme: unknown scheme -> named error.
func TestOpenUnknownScheme(t *testing.T) {
	_, err := Open("nowaysir://foobar")
	if err == nil || !strings.Contains(err.Error(), "nowaysir") {
		t.Errorf("expected error naming the unknown scheme, got %v", err)
	}
}

// TestRegisterPanicsOnEmptyScheme: Register catches obvious misuse
// at package init time rather than silently corrupting the registry.
func TestRegisterPanicsOnEmptyScheme(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Register(\"\", ...) did not panic")
		}
	}()
	Register("", func(url string) (Diviner, error) { return nil, nil })
}

// TestRegisterPanicsOnNilFactory: same discipline.
func TestRegisterPanicsOnNilFactory(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Register(\"x\", nil) did not panic")
		}
	}()
	Register("someNewScheme", nil)
}

// TestRegisterPanicsOnSchemeWithSeparator: reject inputs like
// "gcpkms://" that would trip Open()'s scheme extraction.
func TestRegisterPanicsOnSchemeWithSeparator(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Register with scheme containing :// did not panic")
		}
	}()
	Register("gcpkms://", func(url string) (Diviner, error) { return nil, nil })
}
