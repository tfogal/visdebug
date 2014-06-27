#include <sched.h>
#include <stdio.h>

static const char* SYNCFILE = "/tmp/.garbage";

/* Please please nobody ever find this code and connect it with my name. */
static void
write_0() {
  printf("[ C] writing 0 into %s.\n", SYNCFILE);
  FILE* wr = fopen(SYNCFILE, "w");
  if(fprintf(wr, "%u\n", 0) != 2) {
    perror("writing 0 into file");
  }
  if(fclose(wr) != 0) {
    perror("closing the zero write");
  }
}

static void wait_for_1() {
  unsigned value = 42;
  printf("[ C] waiting for 1...\n");
  do {
    FILE* fp = fopen(SYNCFILE, "r");
    if(!fp) { sched_yield(); continue; }

    value = 42;
    if(fscanf(fp, "%u", &value) != 1) {
      fclose(fp);
      sched_yield();
      continue;
    }
    fclose(fp);
    if(value == 1) { return; }
  } while(value != 1);
}

void
badsync() {
  write_0();
  wait_for_1();
  remove(SYNCFILE);
}
