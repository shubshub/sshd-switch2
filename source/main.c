// SPDX-License-Identifier: GPL-3.0-or-later
// sshd for Switch 2 (kaiHEN): SFTP and a small built-in shell over SSH, on wolfSSH.
// Public-key login only, from sdmc:/switch/sshd/authorized_keys.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdalign.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <switch.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssh/ssh.h>
#include <wolfssh/wolfsftp.h>

#define PORT         2222  /* the Switch refuses homebrew ports below 1024 */
#define MAX_SESSIONS 4
#define CONF_DIR     "sdmc:/switch/sshd"
#define HOST_KEY     CONF_DIR "/ssh_host_ecdsa_key.der"
#define AUTH_KEYS    CONF_DIR "/authorized_keys"

static volatile bool running = true;
// `launch <nro> [arg]`: hbloader loads it once sshd exits (envSetNextLoad).
static volatile bool g_launch;
static char g_next_path[1024], g_next_argv[2100];
static WOLFSSH_CTX* g_ctx;

/* ---- diagnostics: sshd.log step log, crash.txt on a CPU exception ------- */

static FILE* g_log;

static void LOG(const char* fmt, ...) {
    if (!g_log) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

u32 __nx_exception_ignoredebug = 1;
alignas(16) u8 __nx_exception_stack[0x8000];
u64 __nx_exception_stack_size = sizeof(__nx_exception_stack);
extern char __start__[];

/* Records where it died; `addr2line -e sshd.elf <elf+...>` maps it to source.
   Returning hands the crash back to the system as usual. */
void __libnx_exception_handler(ThreadExceptionDump* c) {
    u64 base = (u64)__start__;
    FILE* f = fopen(CONF_DIR "/crash.txt", "w");
    if (!f) return;
    fprintf(f, "error_desc=0x%x far=0x%lx\npc=0x%lx elf+0x%lx\nlr=0x%lx elf+0x%lx\nsp=0x%lx\n",
            c->error_desc, c->far.x, c->pc.x, c->pc.x - base, c->lr.x, c->lr.x - base, c->sp.x);
    for (int i = 0; i < 29; i++) fprintf(f, "x%d=0x%lx\n", i, c->cpu_gprs[i].x);
    fclose(f);
}

int sshd_rand_seed(unsigned char* out, unsigned int sz) {
    randomGet(out, sz);
    return 0;
}

/* SFTP setstat calls these; the SD card (FAT/exFAT) has no owners. */
int chown(const char* p, uid_t u, gid_t g) { (void)p; (void)u; (void)g; return 0; }
int fchown(int fd, uid_t u, gid_t g) { (void)fd; (void)u; (void)g; return 0; }

/* ---- host key ---------------------------------------------------------- */

static void put_str(byte* buf, word32* n, const void* s, word32 len) {
    buf[(*n)++] = len >> 24; buf[(*n)++] = len >> 16;
    buf[(*n)++] = len >> 8;  buf[(*n)++] = len;
    memcpy(buf + *n, s, len);
    *n += len;
}

/* Loads the host key, generating it on first run. Writes its OpenSSH
   fingerprint to fp so the user can check it on first connect. */
static int host_key(byte* der, word32 cap, word32* derSz, char* fp, size_t fpSz) {
    ecc_key key;
    WC_RNG rng;
    word32 idx = 0;
    int ret = -1;

    FILE* f = fopen(HOST_KEY, "rb");
    *derSz = f ? fread(der, 1, cap, f) : 0;
    if (f) fclose(f);

    if (wc_ecc_init(&key) || wc_InitRng(&rng)) return -1;
    if (*derSz == 0) {
        printf("Generating host key...\n");
        consoleUpdate(NULL);
        int n = -1;
        if (wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1) == 0)
            n = wc_EccKeyToDer(&key, der, cap);
        if (n <= 0 || !(f = fopen(HOST_KEY, "wb"))) goto out;
        *derSz = n;
        bool ok = fwrite(der, 1, n, f) == (size_t)n;
        fclose(f);
        if (!ok) goto out;
    } else if (wc_EccPrivateKeyDecode(der, &idx, &key, *derSz)) {
        goto out;
    }

    byte q[72], blob[128], hash[WC_SHA256_DIGEST_SIZE], b64[64];
    word32 qSz = sizeof(q), n = 0, b64Sz = sizeof(b64);
    if (wc_ecc_export_x963(&key, q, &qSz)) goto out;
    put_str(blob, &n, "ecdsa-sha2-nistp256", 19);
    put_str(blob, &n, "nistp256", 8);
    put_str(blob, &n, q, qSz);
    if (wc_Sha256Hash(blob, n, hash) || Base64_Encode_NoNl(hash, sizeof(hash), b64, &b64Sz)) goto out;
    while (b64Sz && (b64[b64Sz - 1] == '=' || b64[b64Sz - 1] == 0)) b64Sz--;
    snprintf(fp, fpSz, "SHA256:%.*s", (int)b64Sz, b64);
    ret = 0;
out:
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    return ret;
}

/* ---- authentication ---------------------------------------------------- */

static int auth_types(WOLFSSH* ssh, void* ctx) {
    (void)ssh; (void)ctx;
    return WOLFSSH_USERAUTH_PUBLICKEY;
}

/* Accepts a key only if its blob matches a line of authorized_keys. wolfSSH
   checks the signature; this checks the key is one we trust. Lines with
   OpenSSH options (from=, command=, ...) never match, so they are refused
   rather than honoured partially. */
static int user_auth(byte type, WS_UserAuthData* d, void* ctx) {
    (void)ctx;
    if (type != WOLFSSH_USERAUTH_PUBLICKEY) return WOLFSSH_USERAUTH_FAILURE;

    const WS_UserAuthData_PublicKey* pk = &d->sf.publicKey;
    FILE* f = fopen(AUTH_KEYS, "r");
    if (!f) return WOLFSSH_USERAUTH_FAILURE;

    static __thread char line[8192];
    static __thread byte blob[4096];
    bool ok = false;
    while (!ok && fgets(line, sizeof(line), f)) {
        char* save;
        char* ktype = strtok_r(line, " \t\r\n", &save);
        char* b64 = strtok_r(NULL, " \t\r\n", &save);
        if (!ktype || !b64 || ktype[0] == '#') continue;
        word32 n = sizeof(blob);
        ok = Base64_Decode((byte*)b64, strlen(b64), blob, &n) == 0 &&
             n == pk->publicKeySz && memcmp(blob, pk->publicKey, n) == 0;
    }
    fclose(f);
    return ok ? WOLFSSH_USERAUTH_SUCCESS : WOLFSSH_USERAUTH_FAILURE;
}

/* ---- shell ------------------------------------------------------------- */

typedef struct {
    WOLFSSH* ssh;
    char cwd[1024];  /* "/..." on sdmc */
    bool tty;        /* interactive: translate \n to \r\n */
} Sess;

static int is_transient(WOLFSSH* ssh, int r) {
    int e = wolfSSH_get_error(ssh);
    return r == WS_REKEYING || r == WS_WINDOW_FULL || e == WS_WANT_READ ||
           e == WS_WANT_WRITE || e == WS_REKEYING || e == WS_WINDOW_FULL || e == WS_CHAN_RXD;
}

static bool send_all(Sess* s, const void* p, int n) {
    const byte* b = p;
    while (n > 0) {
        int r = wolfSSH_stream_send(s->ssh, (byte*)b, n);
        if (r > 0) { b += r; n -= r; continue; }
        if (!is_transient(s->ssh, r)) return false;
        wolfSSH_worker(s->ssh, NULL);   /* take in window adjusts / rekey */
    }
    return true;
}

static bool send_text(Sess* s, const char* t, int n) {
    if (!s->tty) return send_all(s, t, n);
    int start = 0;
    for (int i = 0; i < n; i++) {
        if (t[i] != '\n') continue;
        if (!send_all(s, t + start, i - start) || !send_all(s, "\r\n", 2)) return false;
        start = i + 1;
    }
    return send_all(s, t + start, n - start);
}

static void out(Sess* s, const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > (int)sizeof(buf) - 1) n = sizeof(buf) - 1;
    if (n > 0) send_text(s, buf, n);
}

/* Resolves arg against cwd into "sdmc:/a/b", handling . and .. */
static void resolve(const Sess* s, const char* arg, char* res, size_t sz) {
    char tmp[1024];
    char* parts[128];
    int np = 0;
    if (!arg || !*arg) arg = ".";
    if (!strncmp(arg, "sdmc:", 5)) arg += 5;
    snprintf(tmp, sizeof(tmp), arg[0] == '/' ? "%s" : "%s/%s", arg[0] == '/' ? arg : s->cwd, arg);

    char* save;
    for (char* t = strtok_r(tmp, "/", &save); t; t = strtok_r(NULL, "/", &save)) {
        if (!strcmp(t, ".")) continue;
        if (!strcmp(t, "..")) { if (np) np--; continue; }
        if (np < 128) parts[np++] = t;
    }
    size_t n = snprintf(res, sz, "sdmc:");
    if (!np) snprintf(res + n, sz - n, "/");
    for (int i = 0; i < np && n < sz; i++) n += snprintf(res + n, sz - n, "/%s", parts[i]);
}

/* Splits a line into words; "double quotes" keep spaces. */
static int split(char* line, char** argv, int max) {
    int argc = 0;
    while (*line && argc < max) {
        while (*line == ' ' || *line == '\t') line++;
        if (!*line) break;
        char quote = *line == '"' ? *line++ : 0;
        argv[argc++] = line;
        while (*line && (quote ? *line != quote : (*line != ' ' && *line != '\t'))) line++;
        if (*line) *line++ = 0;
    }
    return argc;
}

static int cmd_ls(Sess* s, const char* path) {
    char dir[1024], full[1536];
    resolve(s, path, dir, sizeof(dir));
    DIR* d = opendir(dir);
    if (!d) { out(s, "ls: %s: cannot open\n", dir); return 1; }
    struct dirent* e;
    while ((e = readdir(d))) {
        struct stat st;
        snprintf(full, sizeof(full), "%s/%s", strcmp(dir, "sdmc:/") ? dir : "sdmc:", e->d_name);
        bool isdir = stat(full, &st) == 0 && S_ISDIR(st.st_mode);
        if (isdir) out(s, "d %12s  %s/\n", "", e->d_name);
        else       out(s, "- %12lld  %s\n", (long long)st.st_size, e->d_name);
    }
    closedir(d);
    return 0;
}

static int cmd_cat(Sess* s, const char* path) {
    char p[1024], buf[4096];
    resolve(s, path, p, sizeof(p));
    FILE* f = fopen(p, "rb");
    if (!f) { out(s, "cat: %s: cannot open\n", p); return 1; }
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        if (!send_text(s, buf, n)) break;
    fclose(f);
    return 0;
}

/* Runs one command line. Returns the exit status, or -1 to end the session. */
static int run_cmd(Sess* s, char* line) {
    char* argv[8];
    char a[1024], b[1024];
    int argc = split(line, argv, 8);
    if (!argc) return 0;
    const char* c = argv[0];
    const char* x = argc > 1 ? argv[1] : NULL;

    if (!strcmp(c, "exit") || !strcmp(c, "logout")) return -1;
    if (!strcmp(c, "help")) {
        out(s, "ls [dir]  cd [dir]  pwd  cat <file>  mkdir <dir>  rmdir <dir>\n"
               "rm <file>  mv <from> <to>  launch <nro> [arg]  exit\n"
               "Paths are on the SD card. Use sftp/scp to copy files.\n");
        return 0;
    }
    if (!strcmp(c, "pwd")) { out(s, "%s\n", s->cwd); return 0; }
    if (!strcmp(c, "ls"))  return cmd_ls(s, x);
    if (!strcmp(c, "cd")) {
        struct stat st;
        resolve(s, x ? x : "/", a, sizeof(a));
        if (stat(a, &st) || !S_ISDIR(st.st_mode)) { out(s, "cd: %s: not a directory\n", a); return 1; }
        snprintf(s->cwd, sizeof(s->cwd), "%s", a + 5);
        return 0;
    }
    if (!strcmp(c, "launch")) {
        if (!x) { out(s, "launch: need an .nro path\n"); return 1; }
        resolve(s, x, a, sizeof(a));
        snprintf(g_next_path, sizeof(g_next_path), "%s", a);
        snprintf(g_next_argv, sizeof(g_next_argv), "%s%s%s", a, argc > 2 ? " " : "", argc > 2 ? argv[2] : "");
        g_launch = true;
        out(s, "launching %s when this session closes; sshd exits\n", a);
        return 0;
    }
    if (!x) { out(s, "%s: missing argument (try help)\n", c); return 1; }
    resolve(s, x, a, sizeof(a));
    int r;
    if      (!strcmp(c, "cat"))   return cmd_cat(s, x);
    else if (!strcmp(c, "mkdir")) r = mkdir(a, 0777);
    else if (!strcmp(c, "rmdir")) r = rmdir(a);
    else if (!strcmp(c, "rm"))    r = unlink(a);
    else if (!strcmp(c, "mv")) {
        if (argc < 3) { out(s, "mv: need <from> <to>\n"); return 1; }
        resolve(s, argv[2], b, sizeof(b));
        r = rename(a, b);
    } else { out(s, "%s: unknown command (try help)\n", c); return 127; }
    if (r) out(s, "%s: %s: failed\n", c, a);
    return r ? 1 : 0;
}

static void prompt(Sess* s) { out(s, "switch2:%s$ ", s->cwd); }

static void shell(Sess* s) {
    char line[512];
    byte in[256], prev = 0;
    int len = 0, esc = 0;
    out(s, "Switch 2 sshd. Type 'help' for commands.\n");
    prompt(s);
    for (;;) {
        int r = wolfSSH_stream_read(s->ssh, in, sizeof(in));
        if (r <= 0) {
            if (running && is_transient(s->ssh, r)) continue;
            return;
        }
        for (int i = 0; i < r; prev = in[i++]) {
            byte c = in[i];
            if (esc) {                       /* skip ESC [ ... final-byte (arrow keys etc.) */
                if (esc == 1 && c == '[') esc = 2;
                else if (esc == 1 || (c >= 0x40 && c <= 0x7e)) esc = 0;
                continue;
            }
            if (c == 0x1b) { esc = 1; continue; }
            if (c == '\n' && prev == '\r') continue;
            if (c == '\r' || c == '\n') {
                out(s, "\n");
                line[len] = 0;
                len = 0;
                if (run_cmd(s, line) < 0) return;
                prompt(s);
            } else if (c == 0x7f || c == 0x08) {
                if (len) { len--; send_all(s, "\b \b", 3); }
            } else if (c == 0x03) {
                len = 0;
                out(s, "^C\n");
                prompt(s);
            } else if (c == 0x04) {
                if (!len) return;
            } else if (c >= 0x20 && len < (int)sizeof(line) - 1) {
                line[len++] = c;
                send_all(s, &c, 1);
            }
        }
    }
}

/* ---- SFTP -------------------------------------------------------------- */

/* Serves SFTP until the client leaves: pending replies first, then any
   packets on the socket, then any request the channel holds. */
static void sftp(WOLFSSH* ssh) {
    int fd = wolfSSH_get_fd(ssh), ret = WS_SUCCESS, err;
    byte peek;
    while (running) {
        if (wolfSSH_SFTP_PendingSend(ssh)) {
            ret = wolfSSH_SFTP_read(ssh);
            err = wolfSSH_get_error(ssh);
            if (err == WS_EOF) return;
            if (err == WS_WANT_WRITE) continue;
        }

        struct pollfd p = { .fd = fd, .events = POLLIN };
        int pr = poll(&p, 1, 1000);
        if (pr < 0 || (p.revents & (POLLERR | POLLNVAL))) return;
        if (pr > 0 || ret == WS_WANT_READ || ret == WS_WANT_WRITE) {
            ret = wolfSSH_worker(ssh, NULL);
            err = wolfSSH_get_error(ssh);
            if (ret == WS_REKEYING) continue;
            if (err == WS_WANT_READ || err == WS_WANT_WRITE || err == WS_WINDOW_FULL) { ret = err; continue; }
            if (err == WS_EOF) {
                int pk = wolfSSH_stream_peek(ssh, NULL, 1);
                if (pk != WS_REKEYING && pk <= 0) return;
            }
            if (ret != WS_SUCCESS && ret != WS_CHAN_RXD && ret != WS_EOF) return;
        }

        ret = wolfSSH_stream_peek(ssh, &peek, 1);
        if (ret > 0) {
            ret = wolfSSH_SFTP_read(ssh);
            err = wolfSSH_get_error(ssh);
            if (err == WS_EOF) return;
            if (is_transient(ssh, ret)) ret = err;
            else if (ret < 0) return;
        } else if (ret < 0 && ret != WS_REKEYING) {
            if (wolfSSH_get_error(ssh) == WS_EOF) return;
            WOLFSSH_CHANNEL* ch = wolfSSH_ChannelNext(ssh, NULL);
            if (!ch || wolfSSH_ChannelGetEof(ch)) return;
        }
    }
}

/* ---- sessions ---------------------------------------------------------- */

typedef struct {
    Thread thread;
    int fd;
    char peer[INET_ADDRSTRLEN];
    bool used;
    volatile bool done;
} Slot;

static Slot slots[MAX_SESSIONS];

static void session(Slot* slot) {
    WOLFSSH* ssh = wolfSSH_new(g_ctx);
    if (!ssh) return;
    wolfSSH_set_fd(ssh, slot->fd);

    int ret = wolfSSH_accept(ssh);
    struct timeval none = { 0, 0 };
    setsockopt(slot->fd, SOL_SOCKET, SO_RCVTIMEO, &none, sizeof(none));

    if (ret == WS_SFTP_COMPLETE) {
        printf("%s: sftp (%s)\n", slot->peer, wolfSSH_GetUsername(ssh));
        wolfSSH_SFTP_SetDefaultPath(ssh, "/");
        sftp(ssh);
    } else if (ret == WS_SUCCESS) {
        Sess s = { .ssh = ssh, .cwd = "/" };
        int status = 0;
        switch (wolfSSH_GetSessionType(ssh)) {
        case WOLFSSH_SESSION_SHELL:
            printf("%s: shell (%s)\n", slot->peer, wolfSSH_GetUsername(ssh));
            s.tty = true;
            shell(&s);
            break;
        case WOLFSSH_SESSION_EXEC: {
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "%s", wolfSSH_GetSessionCommand(ssh));
            printf("%s: exec %s\n", slot->peer, cmd);
            status = run_cmd(&s, cmd);
            break;
        }
        default:
            status = 1;
        }
        wolfSSH_stream_exit(ssh, status < 0 ? 0 : status);
    } else {
        printf("%s: rejected (%s)\n", slot->peer, wolfSSH_ErrorToName(wolfSSH_get_error(ssh)));
    }
    wolfSSH_shutdown(ssh);
    wolfSSH_free(ssh);
}

static void session_thread(void* arg) {
    Slot* slot = arg;
    session(slot);
    printf("%s: closed\n", slot->peer);
    slot->done = true;
}

/* Joins finished sessions; with stop, ends the live ones first. */
static void reap(bool stop) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        Slot* s = &slots[i];
        if (!s->used || (!stop && !s->done)) continue;
        if (!s->done) shutdown(s->fd, SHUT_RDWR);
        threadWaitForExit(&s->thread);
        threadClose(&s->thread);
        close(s->fd);
        s->used = false;
    }
}

static void accept_one(int lfd) {
    struct sockaddr_in a;
    socklen_t al = sizeof(a);
    int fd = accept(lfd, (struct sockaddr*)&a, &al);
    if (fd < 0) return;

    Slot* slot = NULL;
    for (int i = 0; i < MAX_SESSIONS && !slot; i++)
        if (!slots[i].used) slot = &slots[i];
    if (!slot) { close(fd); printf("Busy: refused a connection\n"); return; }

    /* ponytail: 30 s per read during login stops a silent client holding a
       slot; a slow trickle still can, fine on a home LAN. */
    struct timeval tv = { 30, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    *slot = (Slot){ .fd = fd, .used = true };
    inet_ntop(AF_INET, &a.sin_addr, slot->peer, sizeof(slot->peer));
    if (R_FAILED(threadCreate(&slot->thread, session_thread, slot, NULL, 0x80000, 0x2C, -2)) ||
        R_FAILED(threadStart(&slot->thread))) {
        close(fd);
        slot->used = false;
    }
}

/* ---- main -------------------------------------------------------------- */

int main(void) {
    static byte der[512];
    word32 derSz;
    char fp[64];
    int lfd = -1;

    mkdir(CONF_DIR, 0777);
    remove(CONF_DIR "/crash.txt");
    g_log = fopen(CONF_DIR "/sshd.log", "w");
    LOG("start base=0x%lx", (u64)__start__);
    {   // what the loader says about the program that ran before us
        FILE* f = fopen(CONF_DIR "/lastload.txt", "w");
        u64 pid = 0;
        svcGetProcessId(&pid, CUR_PROCESS_HANDLE);
        if (f) { fprintf(f, "last load %#x pid %lu uptime %lu s\n", envGetLastLoadResult(), pid, armTicksToNs(armGetSystemTick()) / 1000000000); fclose(f); }
    }

    consoleInit(NULL);
    LOG("consoleInit ok");
    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);
    LOG("pad ok");
    Result rc = socketInitializeDefault();
    LOG("socketInitializeDefault rc=0x%x", rc);
    chdir("sdmc:/");

    printf("Switch 2 sshd\n\n");
    consoleUpdate(NULL);
    if (wolfSSH_Init() != WS_SUCCESS || !(g_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL))) {
        LOG("wolfSSH init failed");
        printf("wolfSSH init failed\n");
        goto wait;
    }
    LOG("wolfSSH ctx ok");
    int hk = host_key(der, sizeof(der), &derSz, fp, sizeof(fp));
    LOG("host_key=%d derSz=%u", hk, derSz);
    if (hk || wolfSSH_CTX_UsePrivateKey_buffer(g_ctx, der, derSz, WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
        printf("Host key failed (%s)\n", HOST_KEY);
        goto wait;
    }
    LOG("host key loaded %s", fp);
    wolfSSH_SetUserAuth(g_ctx, user_auth);
    wolfSSH_SetUserAuthTypes(g_ctx, auth_types);

    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = INADDR_ANY };
    int one = 1;
    lfd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (lfd < 0 || bind(lfd, (struct sockaddr*)&addr, sizeof(addr)) || listen(lfd, 4)) {
        LOG("listen failed fd=%d errno=%d", lfd, errno);
        printf("Cannot listen on port %d\n", PORT);
        goto wait;
    }
    LOG("listening");

    u32 ip = 0;
    if (R_SUCCEEDED(nifmInitialize(NifmServiceType_User))) {
        nifmGetCurrentIpAddress(&ip);
        nifmExit();
    }
    struct in_addr ia = { .s_addr = ip };
    LOG("ip=%s", inet_ntoa(ia));
    printf("Listening on %s:%d\n", inet_ntoa(ia), PORT);
    printf("Host key %s\n", fp);
    if (access(AUTH_KEYS, R_OK))
        printf("\nNo %s yet:\nadd your public key there, or nobody can log in.\n", AUTH_KEYS);
    printf("\nPress + to exit.\n\n");

    LOG("main loop");
wait:
    while (appletMainLoop()) {
        padUpdate(&pad);
        if (padGetButtonsDown(&pad) & HidNpadButton_Plus) break;
        if (lfd >= 0) {
            struct pollfd p = { .fd = lfd, .events = POLLIN };
            if (!g_launch && poll(&p, 1, 50) > 0) accept_one(lfd);
            reap(false);
            if (g_launch) {                        // leave once the requesting session has closed
                bool busy = false;
                for (int i = 0; i < MAX_SESSIONS; i++) busy |= slots[i].used;
                if (!busy) break;
                svcSleepThread(50000000);
            }
        } else {
            svcSleepThread(50000000);
        }
        consoleUpdate(NULL);
    }

    running = false;
    if (lfd >= 0) close(lfd);
    reap(true);
    if (g_ctx) wolfSSH_CTX_free(g_ctx);
    wolfSSH_Cleanup();
    socketExit();
    consoleExit(NULL);
    if (g_launch && envHasNextLoad()) envSetNextLoad(g_next_path, g_next_argv);
    return 0;
}
