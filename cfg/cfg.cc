// Various routines for building the CFG using DynInst.
// Note that we use C allocation routines all over the place, here, because
// we want to pass the memory we create to other languages and it's way easier
// to call 'free' than 'delete' from other languages.
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>
#include <unordered_map>
#include <vector>
#include "CodeObject.h"
#include "compiler.h"
#include "gocfg.h"

using namespace Dyninst;
using namespace ParseAPI;

#ifdef MAIN
static void printdot(const char* program);
static void print_nodes(const struct node* nds, size_t nodes);
static void free_nodes(struct node* nds, size_t nodes);
static struct node* cfgLocal(const char* program, const char* function,
                             size_t* n_nodes);
/* should the program filter out C library/other uninteresting functions? */
static bool filter = false;
/* produce a dot-format output instead of a default custom output? */
static bool dot = false;
static const char* local = NULL;
static const char* addr = NULL;

int
main(int argc, char* argv[])
{
  if(argc <= 1) { std::cerr << "not enough args.\n"; return -1; }
  for(int a=1; a < argc; a++) {
    if(strcmp(argv[a], "-dot") == 0) { dot = true; }
    if(strcmp(argv[a], "-filter") == 0) { filter = true; }
    if(strcmp(argv[a], "-local") == 0) { local = argv[a+1]; }
    if(strcmp(argv[a], "-address") == 0) { addr = argv[a+1]; }
  }

  if(dot) {
    printdot(argv[1]);
  } else {
    size_t nodes;
    struct node* nds;
    if(addr != NULL) {
      unsigned long addrl = strtoul(addr, NULL, 16);
      nds = cfg_address(argv[1], uintptr_t(addrl), &nodes);
    } else if(local == NULL) {
      nds = cfg(argv[1], &nodes);
    } else {
      nds = cfgLocal(argv[1], local, &nodes);
    }
    print_nodes(nds, nodes);
    free_nodes(nds, nodes);
  }
  return EXIT_SUCCESS;
}

static void
print_nodes(const struct node* nds, size_t nodes)
{
  if(nodes == 0) { return; }

  for(size_t n=0; n < nodes; ++n) {
    printf("node %zu: ", n);
    if(nds[n].name) {
      printf("%s(0x%08x), ", nds[n].name, (unsigned)nds[n].addr);
    } else {
      printf("0x%08x, ", (unsigned)nds[n].addr);
    }
    printf("%zu edges.\n", nds[n].edges);
    for(size_t e=0; e < nds[n].edges; ++e) {
      printf("\t0x%08x -> 0x%08x\n", (unsigned)nds[n].edgelist[e].from,
             (unsigned)nds[n].edgelist[e].to);
    }
  }
}

static void
free_nodes(struct node* nds, size_t nodes)
{
  for(size_t n=0; n < nodes; ++n) {
    free((char*)nds[n].name);
    free(nds[n].edgelist);
    nds[n].edgelist = NULL;
  }
  free(nds);
}
#endif

/* predicate for "internal" functions, garbage symbols/fqns that exist in the
 * symbol table but don't actually represent anything of merit. */
static bool internalfqn(/*const*/ Function* f) {
  return f->name().empty() ||
         f->name().front() == '_';
}

PURE
static size_t nblocks(const CodeObject::funclist& fqns,
                      const std::function<bool(Function*)>& filter) {
  std::map<Address, bool> seen;
  size_t blocks = 0;
  for(auto fqn : fqns) {
    if(filter(fqn)) { continue; }
    for(const Block* blk : fqn->blocks()) {
      assert(blk->start() != 0x0);
      // don't get stuck in loops
      if(seen.find(blk->start()) != seen.end()) { continue; }
      seen[blk->start()] = true;
      blocks++;
    }
  }
  return blocks;
}

PURE static size_t
nblocks_fqn(const Function* fqn)
{
  std::map<Address, bool> seen;
  size_t blocks = 0;
  for(const Block* blk : fqn->blocks()) {
    assert(blk->start() != 0x0);
    // don't get stuck in loops
    if(seen.find(blk->start()) != seen.end()) { continue; }
    seen[blk->start()] = true;
    blocks++;
  }
  return blocks;
}


// builds the CFG, but ignores functions which pass the predicate.
static struct node*
cfg_filter(const char* program, std::function<bool(Function*)>& filter,
           size_t* n_nodes)
{
  if(n_nodes == NULL || program == NULL) { errno = EINVAL; return NULL; }

  std::map<Address, bool> seen;
  std::vector<Function*> funcs;

  // SymtabCodeSource modifies the damn argument.
  char* prog = strdup(program);
  std::unique_ptr<SymtabCodeSource> sts(new SymtabCodeSource(prog));
  free(prog);
  // we can't make this a unique_ptr because sts needs to be deleted before the
  // CodeObject, else DynInst blows up and everything breaks.
  CodeObject* co = new CodeObject(sts.get());

  // Parse the binary
  co->parse();

  const CodeObject::funclist& all = co->funcs();
  // use malloc to allocate so Go can use free.
  constexpr size_t sznode = sizeof(struct node);
  struct node* nodes = (struct node*)calloc(nblocks(all, filter), sznode);
  if(nodes == NULL) {
    errno = ENOMEM;
    *n_nodes = 0;
    return NULL;
  }
  *n_nodes = nblocks(all, filter);
  size_t n=0; // we also need an index into the nodes.
  for(auto fqn : all) {
    if(filter(fqn)) { continue; }

    for(const Block* blk : fqn->blocks()) {
      assert(blk->start() != 0x0);
      // detect loops and bail if so.
      if(seen.find(blk->start()) != seen.end()) { continue; }
      seen[blk->start()] = true;

      nodes[n].addr = blk->start();
      nodes[n].name = NULL;
      if(blk->start() == fqn->addr()) {
        nodes[n].name = strdup(fqn->name().c_str());
      }
      constexpr size_t egsz = sizeof(struct edge);
      nodes[n].edgelist = (struct edge*)malloc(egsz*blk->targets().size());
      nodes[n].edges = blk->targets().size();

      size_t e = 0; // edge.
      for(auto jmp : blk->targets()) {
        assert(nodes[n].addr == jmp->src()->start());
        nodes[n].edgelist[e].from = nodes[n].addr;
        nodes[n].edgelist[e].to = jmp->trg()->start();
        nodes[n].edgelist[e].flags = 0; /* FIXME */
        e++;
      }
      assert(nodes[n].addr != 0x0);
      n++;
    }
  }
  delete co;
  return nodes;
}

static struct node*
cfg_from_fqn(Function* fqn, size_t* n_nodes)
{
  std::map<Address, bool> seen;

  // use malloc to allocate so Go can use free.
  constexpr size_t sznode = sizeof(struct node);
  struct node* nodes = (struct node*)calloc(nblocks_fqn(fqn), sznode);
  if(nodes == NULL) {
    errno = ENOMEM;
    *n_nodes = 0;
    return NULL;
  }
  *n_nodes = nblocks_fqn(fqn);

  assert(!internalfqn(fqn));

  size_t n=0;
  for(const Block* blk : fqn->blocks()) {
    assert(blk->start() != 0x0);
    // detect loops and bail if so.
    if(seen.find(blk->start()) != seen.end()) { continue; }
    seen[blk->start()] = true;

    assert(n < *n_nodes);
    nodes[n].addr = blk->start();
    nodes[n].name = NULL;
    if(blk->start() == fqn->addr()) {
      nodes[n].name = strdup(fqn->name().c_str());
    }
    constexpr size_t egsz = sizeof(struct edge);
    nodes[n].edgelist = (struct edge*)malloc(egsz*blk->targets().size());
    nodes[n].edges = blk->targets().size();

    size_t e = 0; // edge.
    for(auto jmp : blk->targets()) {
      assert(nodes[n].addr == jmp->src()->start());
      nodes[n].edgelist[e].from = nodes[n].addr;
      nodes[n].edgelist[e].to = jmp->trg()->start();
      nodes[n].edgelist[e].flags = 0; /* FIXME */
      e++;
    }
    assert(nodes[n].addr != 0x0);
    n++;
  }
  return nodes;
}

extern "C" struct node*
cfg(const char* program, size_t* n_nodes)
{
  std::function<bool(Function*)> f = internalfqn;
  return cfg_filter(program, f, n_nodes);
}

EXTC struct node*
cfg_address(const char* program, const uintptr_t address, size_t* nnodes)
{
  *nnodes = 0;
  // SymtabCodeSource modifies the damn argument.
  char* prog = strdup(program);
  SymtabCodeSource* sts = new SymtabCodeSource(prog);
  free(prog);

  const std::vector<CodeRegion*>& regions = sts->regions();
  CodeRegion* funcregion = NULL;
  for(auto rgn : regions) {
    if(rgn->contains(address)) {
      funcregion = rgn;
    }
  }

  std::unique_ptr<CodeObject> co(new CodeObject(sts));
  co->parse(static_cast<Dyninst::Address>(address), false);
  Function* f = co->findFuncByEntry(funcregion, address);
  assert(f != NULL);
  f->blocks(); // we do this because it finalize()s the fqn (as a side effect)
  return cfg_from_fqn(f, nnodes);
}

#ifdef MAIN
// Like 'cfg' but only builds the CFG for a local graph.
static struct node*
cfgLocal(const char* program, const char* function, size_t* n_nodes)
{
  // This is unfortunately not great; we just create a predicate that
  // matches the name of the function that DynInst finds.  So, DynInst
  // is probably still *building* the full CFG for basic blocks outside
  // the given function, and we're just filtering it out.  Oh well, we
  // acquiesce for now, since there doesn't seem to be a way around it
  // without hacking DynInst.
  std::function<bool(Function*)> f = [&](Function* fqn) {
    return internalfqn(fqn) ||
           fqn->name().find(std::string(function)) == std::string::npos;
  };
  return cfg_filter(program, f, n_nodes);
}

/* functions to remove/ignore. */
static const std::array<std::string,7> ignored = {
  "atoi", "deregister_tm_clones", "fwrite", "frame_dummy", "printf", //"puts",
  "register_tm_clones"
};
static void
printdot(const char* program)
{
  std::map<Address, bool> seen;
  std::vector<Function*> funcs;

  // SymtabCodeSource modifies the damn argument.
  char* prog = strdup(program);
  SymtabCodeSource* sts = new SymtabCodeSource(prog);
  free(prog);
  std::unique_ptr<CodeObject> co(new CodeObject(sts));

  // Parse the binary
  co->parse();

  const CodeObject::funclist& all = co->funcs();

  cout << "digraph Gdot {" << endl;
  auto fit = all.begin();
  for(int i = 0; fit != all.end(); ++fit, i++) { // i is index for clusters
    /*const*/ Function *f = *fit;
    if(internalfqn(f)) { continue; }
    // skip any functions in our list of ignored functions.
    if(filter && std::count_if(ignored.begin(), ignored.end(),
       [&](const std::string& s) { return s == f->name(); }) > 0) {
      continue;
    }
    // if producing a local CFG, skip functions that don't match the name.
    if(local && f->name() != std::string(local)) { continue; }

    // Make a cluster for nodes of this function
    cout << "\t subgraph cluster_" << i
         << " { \n\t\t label=\"" << f->name() << "\";\n"
         << "\t\t color=blue;" << endl;
    cout << "\t\t\"" << hex << f->addr() << dec << "\" [shape=box";
    if (f->retstatus() == NORETURN) {
      cout << ",color=red";
    }
    cout << "]" << endl;

    // Label functions by name
    cout << "\t\t\"" << hex << f->addr() << dec
         << "\" [label = \""
         << f->name() << "\\n" << hex << f->addr() << dec
         << "\"];" << endl;
    std::stringstream edgeoutput;
    for(const Block* b : f->blocks()) {
      // Don't revisit blocks
      if(seen.find(b->start()) != seen.end()) {
        continue;
      }
      seen[b->start()] = true;
      cout << "\t\t\"" << hex << b->start() << dec << "\";" << endl;

      for(auto it = b->targets().cbegin(); it != b->targets().cend(); ++it) {
        std::string s = "";
        if((*it)->type() == CALL) {
          s = " [color=blue]";
        }
        else if((*it)->type() == RET) {
          s = " [color=green]";
        }

        assert(b->start() == (*it)->src()->start());
        // Store the edges somewhere to be printed outside of the cluster
        edgeoutput << "\t\""
                   << hex << (*it)->src()->start()
                   << "\" -> \""
                   << (*it)->trg()->start()
                   << "\"" << s << endl;
      }
    }
    // End cluster
    cout << "\t}" << endl;
    // Print edges
    cout << edgeoutput.str() << endl;
  }
  cout << "}" << endl;
}
#endif
