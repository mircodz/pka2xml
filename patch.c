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
  { 0x0dff5c0, 0x40, 0xbe }, // mov eax,2
  { 0x0dff5c1, 0x84, 0x02 },
  { 0x0dff5c2, 0xf6, 0x00 },
  { 0x0dff5c3, 0x75, 0x00 },
  { 0x0dff5c4, 0x0b, 0x00 },
  { 0x0dff5c5, 0x31, 0xe9 }, // jmp rel8
  { 0x0dff5c6, 0xf6, 0xf7 },
  { 0x0dff5c7, 0xe9, 0xfe },
  { 0x0dff5c8, 0xf4, 0xff },
  { 0x0dff5c9, 0xfe, 0xff },
  { 0x360fcba, 0x74, 0x90 }, // nops
  { 0x360fcbb, 0x44, 0x90 },
  { 0x360fcbc, 0x0f, 0x90 },
  { 0x360fcbd, 0x1f, 0x90 },
  { 0x360fcbe, 0x40, 0x90 },
  { 0x360fcbf, 0x00, 0x90 },
  { 0x3b514a0, 0x41, 0xb8 }, // mov eax, 0
  { 0x3b514a1, 0x57, 0x00 },
  { 0x3b514a2, 0x41, 0x00 },
  { 0x3b514a3, 0x56, 0x00 },
  { 0x3b514a4, 0x41, 0x00 },
  { 0x3b514a5, 0x55, 0xc3 }, // ret
  { 0x3b5702c, 0x0f, 0x90 }, // nops
  { 0x3b5702d, 0x84, 0x90 },
  { 0x3b5702e, 0x0c, 0x90 },
  { 0x3b5702f, 0x1a, 0x90 },
  { 0x3b57030, 0x00, 0x90 },
  { 0x3b57031, 0x00, 0x90 },
};

static int hexdigit (char c) {
  switch (c) {
    case '0' ... '9': return c - '0';
    case 'A' ... 'F': return 10 + c - 'A';
    case 'a' ... 'f': return 10 + c - 'a';
    default: return -1;
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

  ptrace(PTRACE_ATTACH, process.pid, 0, 0);
  waitpid(process.pid, NULL, 0);

  return process;
}

static void detach(struct process process) { 
  ptrace(PTRACE_DETACH, process.pid, 0, 0);
  close(process.fd);
}

static int apply(struct process process, struct point patch[], int s) {
  for (int i = 0; i < s; i++) {
    printf("0x%x 0x%02x -> 0x%02x\n", (unsigned)patch[i].addr,
        patch[i].a, patch[i].b);

    unsigned char byte = revert ? patch[i].a : patch[i].b;
    int err = pwrite(process.fd, &byte, 1, process.offset + patch[i].addr);
    if (err == -1) printf("err\n");
  }
  return 0;
}

static int assert(struct process process, struct point patch[], int s) {
  for (int i = 0; i < s; i++) {
    unsigned char byte;
    int err = pread(process.fd, &byte, 1, process.offset + patch[i].addr);
    if (err == -1) printf("err\n");

    printf("0x%x %d\n", (unsigned)patch[i].addr, byte == patch[i].a);
  }
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

int main(int argc, char *argv[]) {
  struct process process;

  const char *path = "/opt/packettracer/bin/";
  char filepath[512];
  snprintf(filepath, sizeof(filepath), "LD_LIBRARY_PATH=%s %sPacketTracer7", path, path);

  int pid = fork();
  if (pid < 0) {
  } else if (!pid) {
    chdir(path);
    printf("executing %s", filepath);
    system(filepath);
  } else {
    process = attach("PacketTracer7");
    if (assert(process, patch, SIZEOF(patch))) {
			fprintf(stderr, "bytes don't match\n");
			exit(1);
		}
    apply(process, patch, SIZEOF(patch));
    detach(process);
    wait(0);
    exit(0);
  }

}
