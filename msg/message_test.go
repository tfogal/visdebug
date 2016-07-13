/* Distributed under the MIT license.  See the LICENSE file.
 * Copyright (c) 2014--2016 Thomas Fogal */
package msg

import "os"
import "testing"

func TestAll(t *testing.T) {
	os.Setenv("DEBUG", "+all")
	chn := StdChan("thename")
	chn.Trace("testing")
}

func TestError(t *testing.T) {
	chn := StdChan("thename")
	chn.Error("testing")
}
