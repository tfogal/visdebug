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
#include "CFG.h"
#include "compiler.h"

struct edge {
  uintptr_t from;
  uintptr_t to;
  unsigned flags;
};

struct node {
  uintptr_t addr;
  const char* name;   /* may be null. */
  struct edge* edgelist; /* dynamically allocated. */
  size_t edges;
};

using namespace Dyninst;
using namespace ParseAPI;

#ifdef MAIN
static void printdot(const char* program);
static void print_nodes(const struct node* nds, size_t nodes);
static void free_nodes(struct node* nds, size_t nodes);

int
main(int argc, char* argv[])
{
  bool dot = false;
  if(argc <= 1) { std::cerr << "not enough args.\n"; return -1; }
  if(argc == 3 && strcmp(argv[2], "-dot") == 0) {
    dot = true;
  }

  if(dot) {
    printdot(argv[1]);
  } else {
    size_t nodes;
    struct node* nds = cfg(argv[1], &nodes);
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

/* predicate for filtering functions we don't care about.  if it returns true,
 * we want to process that function. */
static bool functionp(/*const*/ Function* f) {
  return !f->name().empty() &&
          f->name().front() != '_';
}

PURE
static size_t nblocks(const CodeObject::funclist& fqns) {
  std::map<Address, bool> seen;
  size_t blocks = 0;
  for(auto fqn : fqns) {
    if(!functionp(fqn)) { continue; }
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

extern "C" struct node*
cfg(const char* program, size_t* n_nodes)
{
  if(n_nodes == NULL || program == NULL) { errno = EINVAL; return NULL; }

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
  // use malloc to allocate so Go can use free.
  constexpr size_t sznode = sizeof(struct node);
  struct node* nodes = (struct node*)calloc(nblocks(all), sznode);
  if(nodes == NULL) {
    errno = ENOMEM;
    *n_nodes = 0;
    return NULL;
  }
  *n_nodes = nblocks(all);
  size_t n=0; // we also need an index into the nodes.
  for(auto fqn : all) {
    if(!functionp(fqn)) { continue; }

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
  return nodes;
}

#ifdef MAIN
void
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

  cout << "digraph G {" << endl;
  auto fit = all.begin();
  for(int i = 0; fit != all.end(); ++fit, i++) { // i is index for clusters
    /*const*/ Function *f = *fit;
    // Filtering: skip unnamed blocks
    if(f->name().empty()) { continue; }
    //            blocks with names starting with _ are the runtime's.
    if(f->name().front() == '_') { continue; }

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
