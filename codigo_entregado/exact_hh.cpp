// exact_hh.cpp -- Caracterización de la traza y ground truth exacto por ventana.
//
// Tópicos en Grandes Volúmenes de Datos -- material de apoyo, Tarea 1 2026.
//
// Este programa se entrega resuelto y se utiliza como referencia exacta para
// validar las frecuencias, decisiones de heavy hitter y cambios de frecuencia
// estimados por los sketches implementados en la tarea.
//
// Compilación:
//     g++ -O2 -march=native -o exact_hh exact_hh.cpp
//
// Modo 1 -- caracterización global de la traza:
//     ./exact_hh traza.bin --stats --key src --out-rank rank_src.csv
//
// Modo 2 -- ground truth por ventana deslizante:
//     ./exact_hh traza.bin --key src --weight pkts -W 60 --delta 10 --phi 0.01
//         --topk 20 --out-windows win_W60.csv --out-topk topk_W60.csv
//
// Consulta exacta de una o más IP sobre cada ventana:
//     ./exact_hh traza.bin --key src -W 60 --delta 10 --phi 0.01
//         --query 198.18.0.7 --out-query query_exacta.csv
//
// Modo 3 -- perfil de comportamiento de un emisor:
//     ./exact_hh traza.bin --profile auto
//     ./exact_hh traza.bin --profile 203.0.113.9
//
// Claves disponibles (--key):
//     src      IP de origen (32 bits)
//     dst      IP de destino
//     src24    IP de origen enmascarada a /24
//     src16    IP de origen enmascarada a /16
//     5tuple   (src, dst, sport, dport, proto)
//
// Pesos (--weight): pkts (peso 1 por paquete) o bytes (peso = campo len).
//
// Licencia: uso libre para fines docentes.

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

// ------------------------------------------------------ el registro de 24 B
//
// El archivo es una imagen exacta de un arreglo de esta estructura: mismo
// orden de bytes (little-endian) y sin relleno. Por eso se puede mapear y
// castear sin parsear nada. Ver la sección del enunciado sobre little-endian.

#pragma pack(push, 1)
struct Record {
    uint64_t ts_us;
    uint32_t src, dst;
    uint16_t sport, dport, len;
    uint8_t proto, flags;
};
#pragma pack(pop)
static_assert(sizeof(Record) == 24, "el registro debe ocupar 24 bytes");

static const uint8_t F_SYNTHETIC = 0x10;

// ------------------------------------------------------------------ claves
//
// Todas las claves se representan en un entero de 128 bits, de modo que hay
// un solo tipo de tabla hash sin importar la definición elegida. La 5-tupla
// usa 104 bits; las claves de IP usan solo los 32 bits bajos.

typedef unsigned __int128 Key;

enum KeyKind { K_SRC, K_DST, K_SRC24, K_SRC16, K_5TUPLE };

static inline Key make_key(const Record &r, KeyKind k) {
    switch (k) {
    case K_SRC:   return (Key)r.src;
    case K_DST:   return (Key)r.dst;
    case K_SRC24: return (Key)(r.src & 0xFFFFFF00u);  // sobre el ENTERO,
    case K_SRC16: return (Key)(r.src & 0xFFFF0000u);  // no sobre los bytes
    default: {
        uint64_t hi = ((uint64_t)r.src << 32) | (uint64_t)r.dst;
        uint64_t lo = ((uint64_t)r.sport << 24) | ((uint64_t)r.dport << 8) |
                      (uint64_t)r.proto;
        return ((Key)hi << 64) | (Key)lo;
    }
    }
}

static std::string key_to_string(Key k, KeyKind kind) {
    char buf[96];
    auto ip = [](uint32_t v, char *out) {
        sprintf(out, "%u.%u.%u.%u", v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255);
    };
    if (kind == K_5TUPLE) {
        uint64_t hi = (uint64_t)(k >> 64), lo = (uint64_t)k;
        char a[16], b[16];
        ip((uint32_t)(hi >> 32), a);
        ip((uint32_t)hi, b);
        sprintf(buf, "%s:%u->%s:%u/%u", a, (unsigned)((lo >> 24) & 0xFFFF), b,
                (unsigned)((lo >> 8) & 0xFFFF), (unsigned)(lo & 0xFF));
    } else {
        char a[16];
        ip((uint32_t)k, a);
        if (kind == K_SRC24)      sprintf(buf, "%s/24", a);
        else if (kind == K_SRC16) sprintf(buf, "%s/16", a);
        else                      sprintf(buf, "%s", a);
    }
    return std::string(buf);
}

struct KeyHash {
    size_t operator()(Key k) const {
        auto mix = [](uint64_t x) {
            x += 0x9E3779B97F4A7C15ull;
            x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
            x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
            return x ^ (x >> 31);
        };
        return (size_t)(mix((uint64_t)k) ^ mix((uint64_t)(k >> 64)));
    }
};

typedef std::unordered_map<Key, uint64_t, KeyHash> Counter;

// ------------------------------------------------------------------ memoria

static long read_status_kb(const char *field) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long v = -1;
    size_t flen = strlen(field);
    while (fgets(line, sizeof line, f))
        if (strncmp(line, field, flen) == 0) { v = atol(line + flen + 1); break; }
    fclose(f);
    return v;
}

// Estimación del costo real de la tabla hash en libstdc++: un nodo por
// entrada (clave + valor + puntero al siguiente) más el arreglo de buckets.
// Se reporta aparte de VmHWM porque el RSS incluye las páginas de la traza
// mapeada, que no son memoria de la estructura.
static double map_bytes(const Counter &m) {
    double nodes = (double)m.size() * (sizeof(Key) + sizeof(uint64_t) + sizeof(void *));
    double buckets = (double)m.bucket_count() * sizeof(void *);
    return nodes + buckets;
}

// -------------------------------------------------------------------- E/S

struct Trace {
    const Record *r = nullptr;
    size_t n = 0;
    void *addr = nullptr;
    size_t bytes = 0;
};

static Trace map_trace(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open"); exit(1); }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); exit(1); }
    if (st.st_size % (off_t)sizeof(Record)) {
        fprintf(stderr, "error: el tamaño no es múltiplo de 24 B\n");
        exit(1);
    }
    void *p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    close(fd);
    madvise(p, st.st_size, MADV_SEQUENTIAL);
    Trace t;
    t.addr = p;
    t.bytes = st.st_size;
    t.r = (const Record *)p;
    t.n = st.st_size / sizeof(Record);
    return t;
}

// ------------------------------------------------------- modo 1: --stats

static void mode_stats(const Trace &t, KeyKind kind, bool by_bytes,
                       const char *out_rank) {
    Counter c;
    c.reserve(1 << 20);
    uint64_t total_w = 0, total_bytes = 0, syn = 0;
    for (size_t i = 0; i < t.n; ++i) {
        const Record &r = t.r[i];
        uint64_t w = by_bytes ? r.len : 1;
        c[make_key(r, kind)] += w;
        total_w += w;
        total_bytes += r.len;
        if (r.flags & F_SYNTHETIC) syn++;
    }

    std::vector<uint64_t> f;
    f.reserve(c.size());
    for (const auto &kv : c) f.push_back(kv.second);
    std::sort(f.begin(), f.end(), std::greater<uint64_t>());

    uint64_t top10 = 0, top100 = 0, singles = 0;
    for (size_t i = 0; i < f.size(); ++i) {
        if (i < 10)  top10 += f[i];
        if (i < 100) top100 += f[i];
        if (f[i] == 1) singles++;
    }

    double dur = (t.n > 1) ? (double)(t.r[t.n - 1].ts_us - t.r[0].ts_us) / 1e6 : 0.0;
    printf("== caracterización de la traza ==\n");
    printf("registros            : %zu\n", t.n);
    printf("duración             : %.6f s\n", dur);
    printf("tasa media           : %.0f pkt/s, %.3f Gbps\n",
           dur > 0 ? t.n / dur : 0.0, dur > 0 ? total_bytes * 8.0 / dur / 1e9 : 0.0);
    printf("paquetes sintéticos  : %" PRIu64 " (%.4f%%)\n", syn, 100.0 * syn / t.n);
    printf("claves distintas     : %zu\n", c.size());
    printf("  con frecuencia 1   : %" PRIu64 " (%.1f%%)\n", singles,
           100.0 * singles / c.size());
    printf("peso total           : %" PRIu64 " (%s)\n", total_w,
           by_bytes ? "bytes" : "paquetes");
    printf("fracción en el top-10 : %.4f\n", (double)top10 / total_w);
    printf("fracción en el top-100: %.4f\n", (double)top100 / total_w);
    printf("clave más frecuente  : %s\n", [&] {
        for (const auto &kv : c) if (kv.second == f[0]) return key_to_string(kv.first, kind);
        return std::string("?");
    }().c_str());
    printf("  con peso           : %" PRIu64 " (%.4f%% del total)\n", f[0],
           100.0 * f[0] / total_w);
    printf("memoria de la tabla  : %.1f MB (estimada)\n", map_bytes(c) / 1e6);
    printf("VmHWM del proceso    : %.1f MB (incluye la traza mapeada)\n",
           read_status_kb("VmHWM") / 1024.0);

    // Curva rango-frecuencia, submuestreada en escala logarítmica para que el
    // archivo sea manejable sin perder la forma de la cola.
    if (out_rank) {
        FILE *fo = fopen(out_rank, "w");
        if (!fo) { perror("fopen out-rank"); return; }
        fprintf(fo, "rank,freq\n");
        size_t next = 1;
        for (size_t i = 0; i < f.size(); ++i) {
            if (i + 1 >= next || i + 1 == f.size()) {
                fprintf(fo, "%zu,%" PRIu64 "\n", i + 1, f[i]);
                next = (size_t)(next * 1.02) + 1;
            }
        }
        fclose(fo);
        fprintf(stderr, "curva rango-frecuencia escrita en %s\n", out_rank);
    }
}

static bool parse_ipv4(const char *s, uint32_t *out) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

// -------------------------------------------- modo 2: ventana deslizante

struct TopEntry {
    uint64_t count;
    Key key;
    // Comparador invertido: con él, push_heap/pop_heap construyen un MONTÍCULO
    // MÍNIMO por conteo, de modo que heap.front() es el menor de los k mejores
    // y basta compararlo con el candidato. sort_heap con este mismo comparador
    // deja el arreglo ya ordenado de mayor a menor conteo.
    bool operator<(const TopEntry &o) const { return count > o.count; }
};

static void mode_windows(const Trace &t, KeyKind kind, bool by_bytes, double W_s,
                         double delta_s, double phi, size_t topk,
                         const char *out_windows, const char *out_topk,
                         const char *out_query, const std::vector<Key> &queries,
                         size_t max_windows) {
    const uint64_t W = (uint64_t)(W_s * 1e6);
    const uint64_t D = (uint64_t)(delta_s * 1e6);
    if (t.n == 0 || W == 0 || D == 0) return;

    FILE *fw = out_windows ? fopen(out_windows, "w") : nullptr;
    FILE *ft = out_topk ? fopen(out_topk, "w") : nullptr;
    FILE *fq = out_query ? fopen(out_query, "w") : nullptr;
    if (out_windows && !fw) { perror("fopen out-windows"); exit(1); }
    if (out_topk && !ft) { perror("fopen out-topk"); exit(1); }
    if (out_query && !fq) { perror("fopen out-query"); exit(1); }
    if (fw) fprintf(fw, "win,tau_us,N,distinct,threshold,n_hh\n");
    if (ft) fprintf(ft, "win,tau_us,rank,key,count,is_hh\n");
    if (fq) fprintf(fq, "win,tau_us,t_rel_s,key,N,threshold,exact_f,exact_hh,exact_delta\n");

    Counter c;
    c.reserve(1 << 20);

    size_t lo = 0, hi = 0;      // la ventana vigente es [lo, hi)
    uint64_t N = 0;             // peso total dentro de la ventana
    size_t win = 0;
    double sum_distinct = 0;
    size_t max_distinct = 0;
    double max_map_mb = 0;

    const uint64_t t0 = t.r[0].ts_us, tend = t.r[t.n - 1].ts_us;
    if (t0 + W > tend) {
        fprintf(stderr,
                "aviso: la ventana de %.3f s no cabe en una traza de %.3f s; "
                "no se evaluó ninguna ventana\n",
                W_s, (double)(tend - t0) / 1e6);
    }
    std::vector<TopEntry> heap;
    heap.reserve(topk + 1);
    std::vector<uint64_t> prev_query(queries.size(), 0);
    bool have_prev_query = false;

    for (uint64_t tau = t0 + W; tau <= tend; tau += D) {
        // Entra todo lo que ocurrió hasta tau...
        while (hi < t.n && t.r[hi].ts_us <= tau) {
            uint64_t w = by_bytes ? t.r[hi].len : 1;
            c[make_key(t.r[hi], kind)] += w;
            N += w;
            hi++;
        }
        // ...y sale todo lo anterior a tau - W. Cada registro se agrega y se
        // quita exactamente una vez, así que el costo total del deslizamiento
        // es lineal en el número de paquetes, no en el número de ventanas.
        while (lo < hi && t.r[lo].ts_us <= tau - W) {
            uint64_t w = by_bytes ? t.r[lo].len : 1;
            Key k = make_key(t.r[lo], kind);
            auto it = c.find(k);
            if (it != c.end()) {
                it->second -= w;
                if (it->second == 0) c.erase(it);  // mantiene exacto el conteo
            }                                      // de claves activas
            N -= w;
            lo++;
        }

        // Umbral de heavy hitter. Debe ser el TECHO de phi*N y no el
        // truncamiento: si phi*N = 3.7, la condición f(x) >= 3.7 sobre
        // frecuencias enteras equivale a f(x) >= 4. Truncar dejaría entrar
        // claves con f = 3. Y si phi*N < 1, el umbral efectivo es 1: toda
        // clave presente en la ventana lo supera.
        uint64_t thr = (uint64_t)std::ceil(phi * (double)N);
        if (thr == 0) thr = 1;

        // Top-k por selección con un montículo de tamaño k.
        heap.clear();
        size_t n_hh = 0;
        for (const auto &kv : c) {
            if (kv.second >= thr) n_hh++;
            if (heap.size() < topk) {
                heap.push_back({kv.second, kv.first});
                std::push_heap(heap.begin(), heap.end());
            } else if (kv.second > heap.front().count) {
                std::pop_heap(heap.begin(), heap.end());
                heap.back() = {kv.second, kv.first};
                std::push_heap(heap.begin(), heap.end());
            }
        }
        std::sort_heap(heap.begin(), heap.end());

        if (fw)
            fprintf(fw, "%zu,%" PRIu64 ",%" PRIu64 ",%zu,%" PRIu64 ",%zu\n", win, tau,
                    N, c.size(), thr, n_hh);
        if (ft)
            for (size_t i = 0; i < heap.size(); ++i)
                fprintf(ft, "%zu,%" PRIu64 ",%zu,%s,%" PRIu64 ",%d\n", win, tau, i + 1,
                        key_to_string(heap[i].key, kind).c_str(), heap[i].count,
                        (heap[i].count >= thr) ? 1 : 0);

        // Consulta exacta de claves concretas. A diferencia del top-k, esta
        // salida no depende de que la clave esté entre las k más frecuentes:
        // entrega directamente f_j(x), la decisión HH y Delta f_j(x).
        if (fq) {
            for (size_t z = 0; z < queries.size(); ++z) {
                auto it = c.find(queries[z]);
                uint64_t f = (it == c.end()) ? 0 : it->second;
                fprintf(fq, "%zu,%" PRIu64 ",%.6f,%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%d,",
                        win, tau, (double)(tau - t0) / 1e6,
                        key_to_string(queries[z], kind).c_str(), N, thr, f,
                        (f >= thr) ? 1 : 0);
                if (have_prev_query) {
                    int64_t df = (int64_t)f - (int64_t)prev_query[z];
                    fprintf(fq, "%" PRId64 "\n", df);
                } else {
                    fprintf(fq, "\n");
                }
                prev_query[z] = f;
            }
            have_prev_query = true;
        }

        sum_distinct += (double)c.size();
        if (c.size() > max_distinct) max_distinct = c.size();
        double mb = map_bytes(c) / 1e6;
        if (mb > max_map_mb) max_map_mb = mb;

        if (++win >= max_windows) break;
    }

    if (fw) fclose(fw);
    if (ft) fclose(ft);
    if (fq) fclose(fq);

    printf("== ground truth por ventana ==\n");
    printf("W = %.3f s, delta = %.3f s, phi = %g, k = %zu\n", W_s, delta_s, phi, topk);
    printf("ventanas evaluadas   : %zu\n", win);
    printf("claves activas       : media %.0f, máx %zu\n",
           win ? sum_distinct / win : 0.0, max_distinct);
    printf("memoria de la tabla  : %.1f MB (máx, estimada)\n", max_map_mb);
    printf("VmHWM del proceso    : %.1f MB (incluye la traza mapeada)\n",
           read_status_kb("VmHWM") / 1024.0);
}

// ------------------------------------------------- modo 3: --profile
//
// Caracteriza a un emisor concreto sobre la traza completa. El objetivo es
// responder qué ES esa dirección a partir de su comportamiento, ya que las IP
// de MAWI están anonimizadas y no se pueden consultar en un whois.

static void mode_profile(const Trace &t, const char *who) {
    uint32_t ip = 0;

    // --profile auto: perfila al mayor emisor por paquetes, buscándolo primero.
    if (strcmp(who, "auto") == 0) {
        Counter c;
        c.reserve(1 << 20);
        for (size_t i = 0; i < t.n; ++i) c[(Key)t.r[i].src] += 1;
        uint64_t best = 0;
        for (const auto &kv : c)
            if (kv.second > best) { best = kv.second; ip = (uint32_t)kv.first; }
        fprintf(stderr, "--profile auto: mayor emisor por paquetes\n");
    } else if (!parse_ipv4(who, &ip)) {
        fprintf(stderr, "error: '%s' no es una IPv4 válida ni 'auto'\n", who);
        return;
    }

    uint64_t sent = 0, sent_bytes = 0, recv = 0, recv_bytes = 0;
    uint64_t proto_cnt[256] = {0};
    uint64_t syn_only = 0, tcp = 0;
    uint16_t len_min = 65535, len_max = 0;
    uint64_t first = 0, last = 0;
    std::unordered_map<Key, uint64_t, KeyHash> dsts, dst24, dports;
    std::vector<uint64_t> per_sec;

    for (size_t i = 0; i < t.n; ++i) {
        const Record &r = t.r[i];
        if (r.dst == ip) { recv++; recv_bytes += r.len; }
        if (r.src != ip) continue;
        if (sent == 0) first = r.ts_us;
        last = r.ts_us;
        sent++;
        sent_bytes += r.len;
        proto_cnt[r.proto]++;
        if (r.proto == 6) {
            tcp++;
            if ((r.flags & 0x01) && !(r.flags & 0x02)) syn_only++;  // SYN sin ACK
        }
        if (r.len < len_min) len_min = r.len;
        if (r.len > len_max) len_max = r.len;
        dsts[(Key)r.dst]++;
        dst24[(Key)(r.dst & 0xFFFFFF00u)]++;
        if (r.proto == 6 || r.proto == 17) dports[(Key)r.dport]++;
        size_t s = (size_t)((r.ts_us - first) / 1000000ull);
        if (per_sec.size() <= s) per_sec.resize(s + 1, 0);
        per_sec[s]++;
    }

    char ips[16];
    sprintf(ips, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    printf("== perfil de %s ==\n", ips);
    if (sent == 0) {
        printf("no emitió ningún paquete en esta traza (recibió %" PRIu64 ")\n", recv);
        return;
    }

    double span = (double)(last - first) / 1e6;
    printf("paquetes emitidos    : %" PRIu64 " (%.4f%% de la traza)\n", sent,
           100.0 * sent / t.n);
    printf("bytes emitidos       : %" PRIu64 "\n", sent_bytes);
    printf("paquetes recibidos   : %" PRIu64 " (%" PRIu64 " bytes)\n", recv, recv_bytes);
    printf("razón envío/recepción: %.2f  %s\n", recv ? (double)sent / recv : 0.0,
           (recv == 0 || sent > 20 * recv) ? "<- tráfico casi unidireccional" : "");
    printf("tamaño de paquete    : medio %.1f B, mín %u, máx %u\n",
           (double)sent_bytes / sent, len_min, len_max);

    printf("protocolos           :");
    for (int p = 0; p < 256; ++p)
        if (proto_cnt[p]) {
            const char *nm = (p == 1) ? "ICMP" : (p == 6) ? "TCP" : (p == 17) ? "UDP" : "otro";
            printf(" %s(%d)=%.1f%%", nm, p, 100.0 * proto_cnt[p] / sent);
        }
    printf("\n");
    if (tcp) printf("  TCP con SYN sin ACK: %.1f%%  %s\n", 100.0 * syn_only / tcp,
                    (syn_only > tcp / 2) ? "<- conexiones que no se completan" : "");

    printf("destinos distintos   : %zu  (%.4f destinos por paquete)\n", dsts.size(),
           (double)dsts.size() / sent);
    printf("prefijos /24 tocados : %zu\n", dst24.size());
    printf("duración de actividad: %.3f s de la traza\n", span);
    printf("tasa media           : %.1f pkt/s\n", span > 0 ? sent / span : 0.0);

    // Coeficiente de variación de la tasa por segundo: un valor bajo indica un
    // emisor automático y constante; uno alto, tráfico a ráfagas.
    if (per_sec.size() > 2) {
        double m = 0;
        for (uint64_t v : per_sec) m += (double)v;
        m /= per_sec.size();
        double var = 0;
        for (uint64_t v : per_sec) var += ((double)v - m) * ((double)v - m);
        var /= per_sec.size();
        double cv = m > 0 ? sqrt(var) / m : 0.0;
        printf("regularidad          : CV de la tasa = %.2f  %s\n", cv,
               cv < 0.3 ? "<- muy constante, sugiere un proceso automático"
                        : "<- a ráfagas");
    }

    std::vector<std::pair<uint64_t, uint32_t>> pv;
    for (const auto &kv : dports) pv.push_back({kv.second, (uint32_t)kv.first});
    std::sort(pv.begin(), pv.end(), std::greater<std::pair<uint64_t, uint32_t>>());
    if (!pv.empty()) {
        printf("puertos destino top  :");
        for (size_t i = 0; i < pv.size() && i < 5; ++i)
            printf(" %u(%.1f%%)", pv[i].second, 100.0 * pv[i].first / sent);
        printf("\n");
    }

    printf("\nPistas de lectura: muchos destinos por paquete y una tasa muy constante\n"
           "son la firma de un sondeo automático; un flujo con pocos destinos y\n"
           "paquetes grandes es una transferencia. Contraste este perfil con el que\n"
           "obtiene para el mayor emisor por bytes (--stats --weight bytes).\n");
}

// -------------------------------------------------------------------- main

static void usage(const char *p) {
    fprintf(stderr,
        "uso: %s TRAZA.bin [opciones]\n"
        "  --stats              modo caracterización global\n"
        "  --profile IP|auto    perfil de comportamiento de un emisor\n"
        "  --key K              src (def) | dst | src24 | src16 | 5tuple\n"
        "  --weight W           pkts (def) | bytes\n"
        "  -W SEGUNDOS          ancho de la ventana (def. 60)\n"
        "  --delta SEGUNDOS     paso de la ventana (def. 10)\n"
        "  --phi F              umbral de heavy hitter (def. 0.01)\n"
        "  --topk K             tamaño del top-k (def. 20)\n"
        "  --max-windows N      cortar tras N ventanas (def. sin límite)\n"
        "  --out-rank ARCHIVO   curva rango-frecuencia (con --stats)\n"
        "  --out-windows ARCH   resumen por ventana\n"
        "  --out-topk ARCH      top-k por ventana\n"
        "  --query IP           IP a consultar exactamente; puede repetirse\n"
        "  --out-query ARCH     CSV: f_j(x), HH y Delta f_j(x) para --query\n", p);
}

int main(int argc, char **argv) {
    if (argc < 2 || argv[1][0] == '-') { usage(argv[0]); return argc < 2 ? 2 : 0; }
    const char *path = argv[1];
    bool stats = false, by_bytes = false;
    const char *profile = nullptr;
    KeyKind kind = K_SRC;
    double W = 60.0, delta = 10.0, phi = 0.01;
    size_t topk = 20, max_windows = (size_t)-1;
    const char *o_rank = nullptr, *o_win = nullptr, *o_top = nullptr, *o_query = nullptr;
    std::vector<std::string> query_text;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> const char * {
            if (i + 1 >= argc) { fprintf(stderr, "falta valor para %s\n", a.c_str()); exit(2); }
            return argv[++i];
        };
        if (a == "--stats") stats = true;
        else if (a == "--profile") profile = next();
        else if (a == "--key") {
            std::string k = next();
            if (k == "src") kind = K_SRC;
            else if (k == "dst") kind = K_DST;
            else if (k == "src24") kind = K_SRC24;
            else if (k == "src16") kind = K_SRC16;
            else if (k == "5tuple") kind = K_5TUPLE;
            else { fprintf(stderr, "clave desconocida: %s\n", k.c_str()); return 2; }
        }
        else if (a == "--weight") by_bytes = (std::string(next()) == "bytes");
        else if (a == "-W") W = atof(next());
        else if (a == "--delta") delta = atof(next());
        else if (a == "--phi") phi = atof(next());
        else if (a == "--topk") topk = (size_t)atol(next());
        else if (a == "--max-windows") max_windows = (size_t)atol(next());
        else if (a == "--out-rank") o_rank = next();
        else if (a == "--out-windows") o_win = next();
        else if (a == "--out-topk") o_top = next();
        else if (a == "--query") query_text.emplace_back(next());
        else if (a == "--out-query") o_query = next();
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else { fprintf(stderr, "opción no reconocida: %s\n", argv[i]); return 2; }
    }
    if (delta <= 0) { fprintf(stderr, "--delta debe ser positivo\n"); return 2; }
    if (phi <= 0.0 || phi > 1.0) { fprintf(stderr, "--phi debe estar en (0,1]\n"); return 2; }
    if (!query_text.empty() && !o_query) {
        fprintf(stderr, "--query requiere --out-query ARCHIVO para no mezclar CSV con el resumen\n");
        return 2;
    }
    if (o_query && query_text.empty()) {
        fprintf(stderr, "--out-query requiere al menos un --query IP\n");
        return 2;
    }
    if (!query_text.empty() && kind == K_5TUPLE) {
        fprintf(stderr, "--query IP no está definido para --key 5tuple\n");
        return 2;
    }
    std::vector<Key> queries;
    queries.reserve(query_text.size());
    for (const std::string &q : query_text) {
        uint32_t ip = 0;
        if (!parse_ipv4(q.c_str(), &ip)) {
            fprintf(stderr, "IP inválida en --query: %s\n", q.c_str());
            return 2;
        }
        if (kind == K_SRC24) ip &= 0xFFFFFF00u;
        else if (kind == K_SRC16) ip &= 0xFFFF0000u;
        queries.push_back((Key)ip);
    }

    Trace t = map_trace(path);
    if (profile) mode_profile(t, profile);
    else if (stats) mode_stats(t, kind, by_bytes, o_rank);
    else mode_windows(t, kind, by_bytes, W, delta, phi, topk, o_win, o_top,
                      o_query, queries, max_windows);
    munmap(t.addr, t.bytes);
    return 0;
}
