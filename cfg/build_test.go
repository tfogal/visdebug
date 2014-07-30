// tests building the CFG from a program binary.
package cfg
import "testing"

func TestBuildDimensional(t *testing.T) {
  graph := Build("../testprograms/dimensional")
  if len(graph) < 10 {
    t.Fatalf("'dimensional' graph is way too small: %d nodes.\n", len(graph))
  }
}

func TestBuildDimensionalMain(t *testing.T) {
  full := Build("../testprograms/dimensional")
  main := Local("../testprograms/dimensional", "main")

  if len(main) >= len(full) {
    t.Fatalf("should be *far* fewer symbols in main(%d) than in the whole" +
             " program(%d)", len(main), len(full))
  }
}
