package cfg
import "testing"

type edgedesc struct {
  from, to string
}
type test_el struct {
  nodename string
  edges []edgedesc
}
var eltests = []test_el {
  {"smooth2", []edgedesc{
    edgedesc{"smooth2", "4008e8"},
    edgedesc{"4008e8", "4007fc"},
    edgedesc{"4008e8", "4008fd"},
    edgedesc{"4007fc", "4008e8"},
    edgedesc{"4008fd", "400b20"},
    edgedesc{"400b20", "40090a"},
    edgedesc{"400b20", "400b35"},
    edgedesc{"40090a", "400b06"},
    edgedesc{"400b06", "400b1b"},
    edgedesc{"400b06", "400917"},
    edgedesc{"400b1b", "400b20"},
    edgedesc{"400917", "400b06"},
  }},
}

func TestEdgeListSimple(t *testing.T) {
  a := mkNode("a", 0x400b0a)
  b := mkNode("b", 0x400c0a)
  a.Edgelist = make([]*Edge, 1)
  a.Edgelist[0] = &Edge{b, 0}

  elist := build_edgelist(a)
  if len(elist) != 1 {
    t.Error("expected 1 edge, saw", len(elist), "instead.")
  }
  if elist[0].From.Name != "a" {
    t.Error("'from' edge is messed up.")
  }
  if elist[0].To.Name != "b" {
    t.Error("'to' edge is messed up.")
  }
}

func TestEdgeListSmooth2(t *testing.T) {
  entry := smooth2()
  elist := build_edgelist(entry)

  for _, e := range eltests[0].edges {
    found := false
    for _, eentry := range elist {
      if eentry.From.Name == e.from && eentry.To.Name == e.to {
        found = true
      }
    }
    if !found {
      t.Error("Edge", e, "not found in edge set")
    }
  }
}
