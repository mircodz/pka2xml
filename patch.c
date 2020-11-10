#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h> // open, pid_t
#include <sys/ptrace.h> // ptrace
#include <sys/wait.h> // waitpid
#include <unistd.h> // pread, pwrite

#define SIZEOF(v) (sizeof(v)/sizeof(v[0]))

int revert = 0;

struct point {
  long addr;
  int a;
  int b;
};

struct process {
  pid_t pid;
  int fd;
  long offset;
};

static int hexdigit(char c);
static long parsehex(char *buf);
static long offset(pid_t pid);
static struct process attach(char *name);
static int apply(struct process process, struct point patch[], int s);
static int check(struct process process, struct point patch[], int s);
static pid_t pidof(char *name);

struct point patch[] = {
  { 0xdff5c0, 0x40, 0x90 },
  { 0xdff5c1, 0x84, 0x90 },
  { 0xdff5c2, 0xf6, 0x90 },
  { 0xdff5c3, 0x75, 0x90 },
  { 0xdff5c4, 0x0b, 0x90 },
  { 0xdff5c5, 0x31, 0x90 },
  { 0xdff5c6, 0xf6, 0x90 },
  { 0xdff5c7, 0xe9, 0x90 },
  { 0xdff5c8, 0xf4, 0x90 },
  { 0xdff5c9, 0xfe, 0x90 },
  { 0xdff5ca, 0xff, 0x90 },
  { 0xdff5cb, 0xff, 0x90 },
  { 0xdff5cc, 0x0f, 0x90 },
  { 0xdff5cd, 0x1f, 0x90 },
  { 0xdff5ce, 0x40, 0x90 },
  { 0xdff5cf, 0x00, 0x90 },
};

static int hexdigit (char c) {
  switch (c) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      return c - '0';
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
      return 10 + c - 'A';
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
      return 10 + c - 'a';
    default:
      return -1;
  }
}

static long parsehex(char *buf) {
  long n = 0;
  while (hexdigit(*buf) >= 0) {
    hexdigit(*buf);
    n = (n << 4) + hexdigit(*buf);
    buf++;
  }
  return n;
}

static long offset(pid_t pid) {
  char file[64];
  sprintf(file, "/proc/%d/maps", pid);

  int fd = open(file, O_RDONLY);
  if (fd == -1) printf("err\n");

  char buf[256];
  int err = read(fd, buf, sizeof(buf));
  if (err == -1) printf("err\n");

  close(fd);

  return parsehex(buf);
}

static struct process attach(char *name) {
  struct process process;

  process.pid = pidof(name);
  process.offset = offset(process.pid);

  char file[64];
  sprintf(file, "/proc/%ld/mem", (long)process.pid);
  process.fd = open(file, O_RDWR);

  return process;
}

static int apply(struct process process, struct point patch[], int s) {
  ptrace(PTRACE_ATTACH, process.pid, 0, 0);
  waitpid(process.pid, NULL, 0);

  for (int i = 0; i < s; i++) {
    printf("0x%x 0x%02x -> 0x%02x\n", (unsigned)patch[i].addr,
        patch[i].a, patch[i].b);

    unsigned char byte = revert ? patch[i].a : patch[i].b;
    int err = pwrite(process.fd, &byte, 1, process.offset + patch[i].addr);
    if (err == -1) printf("err\n");
  }
  ptrace(PTRACE_DETACH, process.pid, 0, 0);
  close(process.fd);
  return 0;
}

static int check(struct process process, struct point patch[], int s) {
  ptrace(PTRACE_ATTACH, process.pid, 0, 0);
  waitpid(process.pid, NULL, 0);

  for (int i = 0; i < s; i++) {
    unsigned char byte;
    int err = pread(process.fd, &byte, 1, process.offset + patch[i].addr);
    if (err == -1) printf("err\n");

    printf("0x%x %d\n", (unsigned)patch[i].addr, byte == patch[i].b);
  }
  ptrace(PTRACE_DETACH, process.pid, 0, 0);
  close(process.fd);
  return 0;
}

static pid_t pidof(char *name) {
  char cmd[128];
  sprintf(cmd, "pidof %s", name);
  FILE *fp = popen(cmd, "r");
  fread(cmd, sizeof(char), sizeof(cmd), fp);
  fclose(fp);
  return atoi(cmd);
}

int main() {
  struct process process;

  process = attach("PacketTracer7");
  apply(process, patch, SIZEOF(patch));

  process = attach("PacketTracer7");
  check(process, patch, SIZEOF(patch));
}
