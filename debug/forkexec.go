// +build darwin dragonfly freebsd linux netbsd openbsd
package debug;

/*
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
*/
import "C"
import "unsafe"

func Fork() (int) {
  return int(C.fork())
}

/* creates an array of C strings from an array of Go strings.  Automatically
 * includes a trailing null element.
 * Allocates (C) memory!  You need to C.free every element of the array
 * yourself. */
func cstrarray(arr []string) ([]*C.char) {
  rv := make([]*C.char, len(arr)+1)
  for i:=0; i < len(arr); i++ {
    rv[i] = C.CString(arr[i]);
  }
  rv[len(arr)] = nil;
  return rv;
}

func cfree_str_array(carr []*C.char) {
  for i:=0; i < len(carr); i++ {
    C.free(unsafe.Pointer(carr[i]));
  }
}

func Exec(program string, argv []string, env []string) (error) {
  prog := C.CString(program)
  cargv := cstrarray(argv);
  cenv := cstrarray(env);

  var errno error;
  if(env == nil) {
    _, errno = C.execv(prog, &cargv[0])
  } else {
    _, errno = C.execve(prog, &cargv[0], &cenv[0])
  }

  /* if we're here, Bad Things(tm) have happened. Let's first free up our
   * C-allocated memory. */
  C.free(unsafe.Pointer(prog));
  cfree_str_array(cargv);
  cfree_str_array(cenv);

  return errno;
}
