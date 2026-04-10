// Sandbox module tests: Verify that sandbox implementations correctly
// report availability and names, and that Resolve selects the appropriate
// implementation based on configuration.
package sandbox

import (
	"context"
	"runtime"
	"testing"

	"github.com/TomTonic/extract-sbom/internal/config"
)

// TestPassthroughSandboxAlwaysAvailable verifies that the passthrough
// sandbox reports itself as available on all platforms.
func TestPassthroughSandboxAlwaysAvailable(t *testing.T) {
	t.Parallel()

	sb := NewPassthroughSandbox()
	if !sb.Available() {
		t.Error("PassthroughSandbox.Available() = false, want true")
	}
}

// TestPassthroughSandboxNameIsPassthrough verifies that the passthrough
// sandbox identifies itself as "passthrough" for audit logging.
func TestPassthroughSandboxNameIsPassthrough(t *testing.T) {
	t.Parallel()

	sb := NewPassthroughSandbox()
	if sb.Name() != "passthrough" {
		t.Errorf("PassthroughSandbox.Name() = %q, want %q", sb.Name(), "passthrough")
	}
}

// TestPassthroughSandboxRunFailsForMissingCommand verifies that running
// a nonexistent command returns an error rather than succeeding silently.
func TestPassthroughSandboxRunFailsForMissingCommand(t *testing.T) {
	t.Parallel()

	sb := NewPassthroughSandbox()
	err := sb.Run(context.Background(), "nonexistent-binary-does-not-exist", nil, "/tmp/input", "/tmp/output")
	if err == nil {
		t.Error("expected error for missing command, got nil")
	}
}

// TestBwrapSandboxNotAvailableOnNonLinux verifies that the Bubblewrap
// sandbox correctly reports unavailability on non-Linux platforms.
func TestBwrapSandboxNotAvailableOnNonLinux(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "linux" {
		t.Skip("test only applicable on non-Linux platforms")
	}

	sb := NewBwrapSandbox()
	if sb.Available() {
		t.Error("BwrapSandbox.Available() = true on non-Linux, want false")
	}
}

// TestBwrapSandboxNameIsBwrap verifies the audit-logging name.
func TestBwrapSandboxNameIsBwrap(t *testing.T) {
	t.Parallel()

	sb := NewBwrapSandbox()
	if sb.Name() != "bwrap" {
		t.Errorf("BwrapSandbox.Name() = %q, want %q", sb.Name(), "bwrap")
	}
}

// TestBwrapSandboxRunFailsWhenUnavailable verifies that attempting to
// run a command through an unavailable bwrap sandbox returns an error.
func TestBwrapSandboxRunFailsWhenUnavailable(t *testing.T) {
	t.Parallel()

	sb := NewBwrapSandbox()
	if sb.Available() {
		t.Skip("bwrap is available, cannot test unavailable path")
	}

	err := sb.Run(context.Background(), "echo", []string{"test"}, "/tmp/input", "/tmp/output")
	if err == nil {
		t.Error("expected error when bwrap is unavailable, got nil")
	}
}

// TestResolveReturnsPassthroughWhenUnsafe verifies that Resolve returns
// a PassthroughSandbox when bwrap is unavailable and --unsafe is set.
func TestResolveReturnsPassthroughWhenUnsafe(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "linux" {
		// On Linux, bwrap might be available, so we skip.
		t.Skip("test only reliable on non-Linux")
	}

	cfg := config.DefaultConfig()
	cfg.Unsafe = true

	sb, err := Resolve(cfg)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	if sb.Name() != "passthrough" {
		t.Errorf("Resolve returned %q, want passthrough", sb.Name())
	}
}

// TestResolveReturnsDeniedWhenNotUnsafeAndNoBwrap verifies that Resolve
// returns a DeniedSandbox when bwrap is unavailable and --unsafe is not set.
func TestResolveReturnsDeniedWhenNotUnsafeAndNoBwrap(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "linux" {
		t.Skip("test only reliable on non-Linux where bwrap is absent")
	}

	cfg := config.DefaultConfig()
	cfg.Unsafe = false

	sb, err := Resolve(cfg)
	if err == nil {
		t.Fatal("expected Resolve to return error when bwrap is unavailable and --unsafe=false")
	}
	if sb.Name() != "denied" {
		t.Errorf("Resolve returned %q, want denied", sb.Name())
	}
	if sb.Available() {
		t.Error("DeniedSandbox.Available() = true, want false")
	}

	// Verify that Run returns an error.
	err = sb.Run(context.Background(), "7zz", nil, "/tmp/input", "/tmp/output")
	if err == nil {
		t.Error("DeniedSandbox.Run should always return an error")
	}
}

// TestReplacePrefixExact verifies prefix replacement with exact match.
func TestReplacePrefixExact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		prefix      string
		replacement string
		want        string
	}{
		{
			name: "exact match", input: "/path/to/file",
			prefix: "/path/to/file", replacement: "/new/path", want: "/new/path",
		},
		{
			name: "prefix with trailing path", input: "/path/to/file/sub/dir",
			prefix: "/path/to/file", replacement: "/new/path", want: "/new/path/sub/dir",
		},
		{
			name: "no match", input: "/other/path",
			prefix: "/path/to/file", replacement: "/new/path", want: "/other/path",
		},
		{
			name: "empty strings", input: "",
			prefix: "", replacement: "", want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := replacePrefix(tt.input, tt.prefix, tt.replacement)
			if got != tt.want {
				t.Errorf("replacePrefix(%q, %q, %q) = %q, want %q",
					tt.input, tt.prefix, tt.replacement, got, tt.want)
			}
		})
	}
}

// TestSandboxInterfaceCompliance verifies that both concrete types
// satisfy the Sandbox interface at compile time.
func TestSandboxInterfaceCompliance(t *testing.T) {
	t.Parallel()

	var _ Sandbox = (*BwrapSandbox)(nil)
	var _ Sandbox = (*PassthroughSandbox)(nil)
	var _ Sandbox = (*DeniedSandbox)(nil)
}
