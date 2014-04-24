package cfg
import "testing"

func lassert(t *testing.T, conditional bool, msg string) {
  if !conditional {
    t.Fatalf("%s\n", msg)
    t.FailNow()
  }
}

func TestSingleNodeLoop(t *testing.T) {
  n := mkNode("root", 0x00000042)
  LoopCalc(n)
  lassert(t, !n.InLoop(), "single node is not a loop.")
}

func TestSimpleLoopIsInLoop(t *testing.T) {
  hd := mkNode("root", 0x00000042)
  tail := mkNode("sub", 0x00000084)
  hd.Edgelist = make([]*Edge, 1)
  tail.Edgelist = make([]*Edge, 1)
  hd.Edgelist[0] = &Edge{tail, 0}
  tail.Edgelist[0] = &Edge{hd, 0}

  LoopCalc(hd)
  lassert(t, hd.InLoop(), "2 node loop; both nodes in loop")
  lassert(t, tail.InLoop(), "2 node loop; both nodes in loop")
}

func TestLoopWithExit(t *testing.T) {
  ltest := mkNode("test", 0x00000042)
  body := mkNode("body", 0x00000084)
  done := mkNode("done", 0x00000096)
  ltest.Edgelist = make([]*Edge, 1)
  body.Edgelist = make([]*Edge, 1)
  // no exit from 'done'.
  ltest.Edgelist[0] = &Edge{body, 0}
  body.Edgelist[0] = &Edge{ltest, 0}

  LoopCalc(ltest)
  lassert(t, ltest.InLoop(), "loop test is part of loop")
  lassert(t, body.InLoop(), "body of course is part of loop")
  lassert(t, !done.InLoop(), "exit block is not part of loop!")
}

func TestDistance2Node(t *testing.T) {
  hd := mkNode("root", 0x00000042)
  tail := mkNode("sub", 0x00000084)
  hd.Edgelist = make([]*Edge, 1)
  tail.Edgelist = make([]*Edge, 1)
  hd.Edgelist[0] = &Edge{tail, 0}
  tail.Edgelist[0] = &Edge{hd, 0}

  dist := LoopDist(hd, hd.Edgelist[0])
  lassert(t, dist == uint(2), "distance should be 2")
}

func TestDistanceUnreachable(t *testing.T) {
  /* two isolated loops; should be mostly unreachable. */
  node1 := mkNode("node1", 0x00000042)
  n1sub := mkNode("n1chld", 0x00000084)
  node2 := mkNode("node2", 0x00000019)
  n2sub := mkNode("n2chld", 0x00000038)
  node1.Edgelist = make([]*Edge, 1)
  n1sub.Edgelist = make([]*Edge, 1)
  node1.Edgelist[0] = &Edge{n1sub, 0}
  n1sub.Edgelist[0] = &Edge{node1, 0}

  node2.Edgelist = make([]*Edge, 1)
  n2sub.Edgelist = make([]*Edge, 1)
  node2.Edgelist[0] = &Edge{n2sub, 0}
  n2sub.Edgelist[0] = &Edge{node2, 0}

  lassert(t, 0 == LoopDist(node1, node2.Edgelist[0]), "n1 !reachable from n2")
  lassert(t, 0 == LoopDist(node2, node1.Edgelist[0]), "n2 !reachable from n1")
}

/* 'smooth2' is a (sub)graph copied from a real program which performs a 2d
 * smoothing operation.  there is a 1D loop that primes the top boundary.
 * the smoothing is broken in that it doesn't handle the side and bottom
 * boundaries (which would create 3 more 1D loops), but it is fine for a test
 * program. */
func smooth2() (*Node) {
  entry := mkNode("smooth2", 0x4007e7) // also 4007e7, FWIW.
  n4008e8 := mkNode("4008e8", 0x4008e8)
  n4007fc := mkNode("4007fc", 0x4007fc)
  n4008fd := mkNode("4008fd", 0x4008fd)
  n400b20 := mkNode("400b20", 0x400b20)
  n40090a := mkNode("40090a", 0x40090a)
  n400b35 := mkNode("400b35", 0x400b35)
  n400b06 := mkNode("400b06", 0x400b06)
  n400b1b := mkNode("400b1b", 0x400b1b)
  n400917 := mkNode("400917", 0x400917)

  entry.Edgelist = make([]*Edge, 1)
  entry.Edgelist[0] = &Edge{n4008e8, 0}
  n4008e8.Edgelist = make([]*Edge, 2)
  n4008e8.Edgelist[0] = &Edge{n4007fc, 0}
  n4008e8.Edgelist[1] = &Edge{n4008fd, 0}
  n4007fc.Edgelist = make([]*Edge, 1)
  n4007fc.Edgelist[0] = &Edge{n4008e8, 0}
  n4008fd.Edgelist = make([]*Edge, 1)
  n4008fd.Edgelist[0] = &Edge{n400b20, 0}
  n400b20.Edgelist = make([]*Edge, 2)
  n400b20.Edgelist[0] = &Edge{n40090a, 0}
  n400b20.Edgelist[1] = &Edge{n400b35, 0}
  n40090a.Edgelist = make([]*Edge, 1)
  n40090a.Edgelist[0] = &Edge{n400b06, 0}
  n400b06.Edgelist = make([]*Edge, 2)
  n400b06.Edgelist[0] = &Edge{n400b1b, 0}
  n400b06.Edgelist[1] = &Edge{n400917, 0}
  n400b1b.Edgelist = make([]*Edge, 1)
  n400b1b.Edgelist[0] = &Edge{n400b20, 0}
  n400917.Edgelist = make([]*Edge, 1)
  n400917.Edgelist[0] = &Edge{n400b06, 0}

  return entry
}

func findnode(from *Node, name string) (*Node) {
  sn := make(map[uintptr]bool)
  retval := findnode_h(from, name, sn)
  if retval == nil {
    panic("node was not found, test is broken.")
  }
  return retval
}
func findnode_h(srch *Node, name string, seen map[uintptr]bool) (*Node) {
  if seen[srch.Addr] { return nil }
  seen[srch.Addr] = true
  if srch.Name == name {
    return srch
  }
  for _, edge := range srch.Edgelist {
    n := findnode_h(edge.To, name, seen)
    if n != nil { return n }
  }
  return nil
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
    distance := LoopDist(ntgt, nsrc.Edgelist[tst.edgeidx])
    if distance != tst.result {
      t.Error("For", tst, "expected", tst.result, "got", distance)
    }
  }
}
