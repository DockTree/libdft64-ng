#include <stdio.h>
#include <stdlib.h>

int
main() {
  printf("[APP] Calling malloc...\n");
  char *p = (char *)malloc(10);
  printf("[APP] malloc returned %p\n", p);

  printf("[APP] Calling system...\n");
  system((const char *)p);
  printf("[APP] system returned %p\n", p);

  char *p1 = (char *)malloc(10);
  p1[0] = 'a';

  if (p)
    free(p);

  // uaf
  p[0] = p1[0];

  printf("[APP] Done.\n");
  return 0;
}
