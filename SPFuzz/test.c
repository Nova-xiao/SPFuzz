#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char** argv) {

  char buf[8];
  memset(buf, 0, sizeof(buf));
  buf[0] = "1";

  if (read(0, buf, 8) < 1) {
    printf("Hum?\n");
    exit(1);
  }

  if (buf[0] == '0')
    printf("Looks like a zero to me!\n");
  else
    printf("A non-zero value? How quaint!\n");

  exit(0);

}

