package main;

import(
  "./debug"
  _ "fmt"
)

func main() {
  debug.Blah()
/*
  err := debug.StartUnderOurPurview("/bin/ls", []string{"/bin/ls"});
  if err != nil {
    panic(err.Error());
  }
*/
}
