//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
)

// The Linux broker re-execs this test binary. The production plugin main owns
// the same two child entries; both call NativeChild and do not grow a second policy.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--native-probe":
			os.Exit(0)
		case "--native-child-fd":
			f := os.NewFile(3, "native-specification")
			var spec Spec
			err := json.NewDecoder(io.LimitReader(f, 64<<10)).Decode(&spec)
			_ = f.Close()
			if err != nil {
				os.Exit(126)
			}
			if err = NativeChild(spec); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(126)
			}
			os.Exit(0)
		case "--native-child":
			var spec Spec
			if json.NewDecoder(io.LimitReader(os.Stdin, 64<<10)).Decode(&spec) != nil {
				os.Exit(126)
			}
			if err := NativeChild(spec); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(126)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}
