#include <sched.h>
#include <stdio.h>

static const char* SYNCFILE = "/tmp/.garbage";

/* Please please nobody ever find this code and connect it with my name. */
void
badsync() {
  unsigned value = 42;
  printf("[ C] Waiting for syncfile %s to have a '1' in it...\n", SYNCFILE);
  do {
    FILE* fp = fopen(SYNCFILE, "r");
    if(!fp) { sched_yield(); continue; }

    if(fscanf(fp, "%u", &value) != 1) {
      fclose(fp);
      sched_yield();
      continue;
    }
    fclose(fp);
    if(value == 1) {
      printf("[ C] writing 0 into %s.\n", SYNCFILE);
      FILE* wr = fopen(SYNCFILE, "w");
      if(fprintf(wr, "%u\n", 0) != 2) {
        perror("writing 0 into file");
      }
      if(fclose(wr) != 0) {
        perror("closing the zero write");
      }
      return;
    }
  } while(value != 1);
}
