// Memoizes lookups of complex/difficult to generate computations.
package main

import(
  "./bfd"
  "./cfg"
)

var graphs map[uintptr]map[uintptr]*cfg.Node
func init() {
  graphs = make(map[uintptr]map[uintptr]*cfg.Node)
}
func memocfg(addr *bfd.Symbol) map[uintptr]*cfg.Node {
  if graphs[addr.Address()] == nil {
    g := cfg.FromAddress(globals.program, addr.Address())
    assert(g != nil)
    rn := root_node(g, addr)
    assert(rn != nil)
    cfg.Analyze(rn)
    graphs[addr.Address()] = g
  }
  return graphs[addr.Address()]
}
