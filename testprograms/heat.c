#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* dimensions of the plate to consider. */
static size_t n[2] = {0,0};
/* `temperature' of the constant element, which is the center of the plane. */
static float consttemp = 424.424242f;
/* regression/change must be under this before we terminate. */
static float tolerance = 0.0005;
/* where we will write the final steady state solution. */
static const char* outfn = "out";

#define IDX(x,y) \
  ({ const size_t idx = y*dims[0] + x; idx; })
#define S(x,y) ({ v[IDX(x,y)]; })
__attribute__((noinline)) static bool
relax(float* v, const size_t dims[2], const float tol) {
  const size_t halb[2] = { dims[0] / 2, dims[1] / 2 };
  float change = 0.0f;

  for(size_t y=0; y < dims[1]; ++y) {
    for(size_t x=0; x < dims[0]; ++x) {
      if(halb[0] == x && halb[1] == y) {
        v[IDX(x,y)] = consttemp;
        continue;
      }
      const size_t ay = y == 0 ? 0 : y-1;
      const size_t ax = x == 0 ? 0 : x-1;
      const size_t by = y == dims[1]-1 ? dims[1]-1 : y+1;
      const size_t bx = x == dims[0]-1 ? dims[0]-1 : x+1;
      const float temp = (S(ax,ay) + S( x,ay) + S(bx,ay) +
                          S(ax, y) + S( x, y) + S(bx, y) +
                          S(ax,by) + S( x,by) + S(bx,by)) / 9.0f;
      change += temp - S(x,y);
      S(x,y) = temp;
    }
  }
  return change > tol;
}

static void
usage(const char* program) {
  printf(
"%s -- simulates a temperature dissipating across a 2d plane\n"
"\tx      number of grid points to use in x (uint)\n"
"\ty      number of grid points to use in y (uint)\n"
"\tt      temperature of 'constant' element in the middle (float, %f)\n"
"\tr      regression maximum, termination criterion (float, %f)\n"
"\to      base of the output filename to write (string, %s)\n"
  , program, consttemp, tolerance, outfn);
}

static void
write_field(float* data, const size_t dims[2], const char* basename) {
  char* nhdrnm = calloc(strlen(basename) + 8, sizeof(char));
  strcpy(nhdrnm, basename);
  strcat(nhdrnm, ".nhdr");
  FILE* nhdr = fopen(nhdrnm, "w");
  if(!nhdr) {
    fprintf(stderr, "could not create nhdr '%s'!\n", nhdrnm);
    free(nhdrnm);
    return;
  }
  free(nhdrnm);

  char* outraw = calloc(strlen(basename) + 8, sizeof(char));
  strcpy(outraw, basename);
  strcat(outraw, ".raw");

  /* We pretend it's 3D data just to make e.g. IV3D happy. */
  fprintf(nhdr, "NRRD0001\n");
  fprintf(nhdr, "type: float\n");
  fprintf(nhdr, "dimension: 3\n");
  fprintf(nhdr, "sizes: %zu %zu 1\n", dims[0], dims[1]);
  fprintf(nhdr, "spacings: 1 1 1\n");
  fprintf(nhdr, "endian: little\n");
  fprintf(nhdr, "encoding: raw\n");
  fprintf(nhdr, "data file: %s\n", outraw);
  if(fclose(nhdr) != 0) {
    fprintf(stderr, "error writing nrrd header!\n");
    free(outraw);
    return;
  }
  FILE* raw = fopen(outraw, "wb");
  free(outraw);
  if(!raw) {
    fprintf(stderr, "error writing output file\n");
    return;
  }
  if(fwrite(data, sizeof(float), dims[0]*dims[1], raw) != dims[0]*dims[1]) {
    fprintf(stderr, "error writing data\n");
    return;
  }
  if(fclose(raw) != 0) {
    fprintf(stderr, "error closing raw output file\n");
    return;
  }
}

int
main(int argc, char* argv[]) {
  int opt;
  while((opt = getopt(argc, argv, "x:y:t:r:")) != -1) {
    switch(opt) {
    case 'x':
      n[0] = (size_t)atoi(optarg); /* should be strtoul... */
      break;
    case 'y':
      n[1] = (size_t)atoi(optarg); /* should be strtoul... */
      break;
    case 't':
      consttemp = atof(optarg); /* should be strtod... */
      break;
    case 'r':
      tolerance = atof(optarg); /* should be strtod... */
      break;
    case 'o':
      outfn = optarg;
      break;
    case '?':
      usage(argv[0]);
      exit(EXIT_FAILURE);
    }
  }
  if(n[0]*n[1] == 0) {
    fprintf(stderr, "Dimensions %zux%zu are invalid.\n", n[0], n[1]);
    exit(EXIT_FAILURE);
  }
  float* data = calloc(n[0]*n[1], sizeof(float));
  while(relax(data, n, tolerance)) ;

  write_field(data, n, outfn);
  free(data);
  return 0;
}
