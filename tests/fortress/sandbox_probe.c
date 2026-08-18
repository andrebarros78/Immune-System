#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int network_blocked(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
    return rc != 0;
}

static int child_blocked(void) {
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) _exit(0);
    int status = 0;
    waitpid(pid, &status, 0);
    return 0;
}

static int root_read_only(void) {
    int fd = open("/escape", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 1;
    close(fd);
    unlink("/escape");
    return 0;
}

static int tmp_write_ok(void) {
    int fd = open("/tmp/probe", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;
    const char *msg = "ok";
    int ok = write(fd, msg, 2) == 2;
    close(fd);
    unlink("/tmp/probe");
    return ok;
}

int main(void) {
    int net = network_blocked();
    int child = child_blocked();
    int root_ro = root_read_only();
    int secret_absent = getenv("IMMUNE_PROVIDER_PRIMARY_API_KEY") == NULL && getenv("GLM") == NULL;
    int tmp_ok = tmp_write_ok();
    printf("{\"network_blocked\":%s,\"child_process_blocked\":%s,\"root_read_only\":%s,\"secret_absent\":%s,\"tmp_write_ok\":%s}\n",
        net ? "true" : "false",
        child ? "true" : "false",
        root_ro ? "true" : "false",
        secret_absent ? "true" : "false",
        tmp_ok ? "true" : "false");
    return (net && child && root_ro && secret_absent && tmp_ok) ? 0 : 9;
}
