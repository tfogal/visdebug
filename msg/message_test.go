package msg

import "os"
import "testing"

func TestAll(t *testing.T) {
  os.Setenv("DEBUG", "+all")
  chn := StdChan()
  chn.Trace("testing")
}

func TestError(t *testing.T) {
  chn := StdChan()
  chn.Error("testing")
}
