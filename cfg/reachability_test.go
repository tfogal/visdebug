package cfg
import "fmt"
import "testing"

func TestSingleNode(t *testing.T) {
  n := mkNode("root", 0x00000042)
  fmt.Printf("test is running.\n")
  if Reachable(n, n) {
    t.Fatalf("node should not be reachable from itself.")
  }
}

func TestSimpleLoop(t *testing.T) {
  hd := mkNode("root", 0x00000042)
  tail := mkNode("sub", 0x00000084)
  hd.Edgelist = make([]*Edge, 1)
  tail.Edgelist = make([]*Edge, 1)
  hd.Edgelist[0] = &Edge{tail, 0}
  tail.Edgelist[0] = &Edge{hd, 0}
  if Reachable(tail, hd) == false {
    t.Fatalf("head should be reachable from tail.")
  }
  if Reachable(hd, tail) == false {
   t.Fatalf("tail should be reachable from head")
  }
}

func tassert(t *testing.T, conditional bool, msg string) {
  if !conditional {
    t.Fatalf("%s\n", msg)
    t.FailNow()
  }
}

func TestNormalLoop(t *testing.T) {
  header := mkNode("funcentry", 0x00000001)
  looptest := mkNode("test", 0x00000002)
  body := mkNode("body", 0x00000004)
  post := mkNode("post", 0x00000008)
  header.Edgelist = make([]*Edge, 1)
  looptest.Edgelist = make([]*Edge, 2)
  body.Edgelist = make([]*Edge, 1)

  header.Edgelist[0] = &Edge{looptest, 0}
  looptest.Edgelist[0] = &Edge{body, 0}
  looptest.Edgelist[1] = &Edge{post, 0}
  body.Edgelist[0] = &Edge{looptest, 0}

  r := func(dest *Node, from *Node) (bool) { return Reachable(dest, from); }
  tassert(t, !r(header, looptest), "header unreachable")
  tassert(t, !r(header, body), "header unreachable")
  tassert(t, !r(header, post), "header unreachable")
  tassert(t,  r(looptest, header), "header leads all")
  tassert(t,  r(looptest, body), "direct child")
  tassert(t, !r(looptest, post), "cannot go backwards")
  tassert(t,  r(body, header), "header leads all")
  tassert(t,  r(body, looptest), "direct child")
  tassert(t, !r(body, post), "no link")
  tassert(t,  r(post, header), "header leads all")
  tassert(t,  r(post, looptest), "direct child")
  tassert(t,  r(post, body), "through the looptest")
}
