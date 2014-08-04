package cfg
import "testing"

func lassert(t *testing.T, conditional bool, msg string) {
  if !conditional {
    t.Fatalf("%s\n", msg)
    t.FailNow()
  }
}

func TestSingleNodeLoop(t *testing.T) {
  n := makeNode("root", 0x00000042)
  identify_loops(n)
  lassert(t, !n.InLoop(), "single node is not a loop.")
}

func TestSimpleLoopIsInLoop(t *testing.T) {
  hd := makeNode("root", 0x00000042)
  tail := makeNode("sub", 0x00000084)
  hd.Edgelist = make([]*Edge, 1)
  tail.Edgelist = make([]*Edge, 1)
  hd.Edgelist[0] = &Edge{tail, 0}
  tail.Edgelist[0] = &Edge{hd, 0}

  identify_loops(hd)
  lassert(t, hd.InLoop(), "2 node loop; both nodes in loop")
  lassert(t, tail.InLoop(), "2 node loop; both nodes in loop")
}

func TestLoopWithExit(t *testing.T) {
  ltest := makeNode("test", 0x00000042)
  body := makeNode("body", 0x00000084)
  done := makeNode("done", 0x00000096)
  ltest.Edgelist = make([]*Edge, 1)
  body.Edgelist = make([]*Edge, 1)
  // no exit from 'done'.
  ltest.Edgelist[0] = &Edge{body, 0}
  body.Edgelist[0] = &Edge{ltest, 0}

  identify_loops(ltest)
  lassert(t, ltest.InLoop(), "loop test is part of loop")
  lassert(t, body.InLoop(), "body of course is part of loop")
  lassert(t, !done.InLoop(), "exit block is not part of loop!")
}

func TestDistance2Node(t *testing.T) {
  hd := makeNode("root", 0x00000042)
  tail := makeNode("sub", 0x00000084)
  hd.Edgelist = make([]*Edge, 1)
  tail.Edgelist = make([]*Edge, 1)
  hd.Edgelist[0] = &Edge{tail, 0}
  tail.Edgelist[0] = &Edge{hd, 0}

  dist := loop_distance(hd, hd.Edgelist[0])
  lassert(t, dist == uint(2), "distance should be 2")
}

func TestDistanceUnreachable(t *testing.T) {
  /* two isolated loops; should be mostly unreachable. */
  node1 := makeNode("node1", 0x00000042)
  n1sub := makeNode("n1chld", 0x00000084)
  node2 := makeNode("node2", 0x00000019)
  n2sub := makeNode("n2chld", 0x00000038)
  node1.Edgelist = make([]*Edge, 1)
  n1sub.Edgelist = make([]*Edge, 1)
  node1.Edgelist[0] = &Edge{n1sub, 0}
  n1sub.Edgelist[0] = &Edge{node1, 0}

  node2.Edgelist = make([]*Edge, 1)
  n2sub.Edgelist = make([]*Edge, 1)
  node2.Edgelist[0] = &Edge{n2sub, 0}
  n2sub.Edgelist[0] = &Edge{node2, 0}

  lassert(t, 0 == loop_distance(node1, node2.Edgelist[0]), "n1 !reachable from n2")
  lassert(t, 0 == loop_distance(node2, node1.Edgelist[0]), "n2 !reachable from n1")
}

type testinfo struct {
  source string
  edgeidx uint
  dest string
  result uint
}
var distsmooth2tests = []testinfo {
  {"smooth2", 0, "4008e8", 1},
  {"400b06", 0, "400917", 5}, // 400b06.edge0 leads to 400917 in 5 edges/moves
  {"400917", 0, "40090a", 4},
  {"400b20", 0, "4008e8", 0}, // unreachable.
  {"400b20", 0, "400b20", 4},
  {"400b20", 0, "400b35", 5},
  {"400b06", 1, "400b35", 5},
  {"400b06", 1, "40090a", 5},
}

func TestDistanceSmooth2(t *testing.T) {
  smth2 := smooth2()

  for _, tst := range distsmooth2tests {
    nsrc := findnode(smth2, tst.source)
    ntgt := findnode(smth2, tst.dest)
    distance := loop_distance(ntgt, nsrc.Edgelist[tst.edgeidx])
    if distance != tst.result {
      t.Error("For", tst, "expected", tst.result, "got", distance)
    }
  }
}
