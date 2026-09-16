// pcap2bin.cpp -- Conversor de trazas pcap a registros binarios de ancho fijo.
//
// Tópicos en Grandes Volúmenes de Datos -- material de apoyo, Tarea 1 2026.
//
// Lee un archivo pcap clásico (libpcap) desde stdin o desde un archivo y emite
// por stdout una secuencia de registros de 24 bytes, sin cabecera, uno por
// paquete IP. El objetivo es que el bucle principal de los sketches no tenga
// que parsear pcap: basta con mmap() sobre el archivo de salida y recorrerlo
// como un arreglo de structs.
//
// Compilación:
//     g++ -O2 -march=native -o pcap2bin pcap2bin.cpp
//
// Uso típico:
//     zcat 202501011400.pcap.gz | ./pcap2bin > traza.bin
//     ./pcap2bin -i traza.pcap -o traza.bin
//
// Formato del registro (24 bytes, little-endian, sin padding implícito):
//
//     offset  tipo      campo
//     ------  --------  ------------------------------------------------
//        0    uint64_t  ts_us    microsegundos desde epoch
//        8    uint32_t  src      IPv4 origen en orden de host (little-endian)
//       12    uint32_t  dst      IPv4 destino
//       16    uint16_t  sport    puerto origen (0 si no es TCP/UDP)
//       18    uint16_t  dport    puerto destino (0 si no es TCP/UDP)
//       20    uint16_t  len      largo del paquete en el cable (bytes)
//       22    uint8_t   proto    número de protocolo IP (6=TCP, 17=UDP, 1=ICMP)
//       23    uint8_t   flags    bit 0 SYN, 1 ACK, 2 FIN, 3 RST,
//                                bit 4 SINTÉTICO (lo marca el inyector),
//                                bit 5 el registro proviene de IPv6
//
// Las estadísticas del procesamiento se emiten por stderr, de modo que stdout
// queda limpio para redirigir a un archivo.
//
// Licencia: uso libre para fines docentes.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cinttypes>
#include <string>
#include <vector>

// ---------------------------------------------------------------- constantes

static const uint32_t PCAP_MAGIC_US = 0xa1b2c3d4u; // timestamps en microsegundos
static const uint32_t PCAP_MAGIC_NS = 0xa1b23c4du; // timestamps en nanosegundos
static const uint32_t PCAPNG_MAGIC  = 0x0a0d0d0au; // pcapng: no soportado

// DLT / LINKTYPE que sabemos desencapsular.
static const uint32_t DLT_NULL    = 0;
static const uint32_t DLT_EN10MB  = 1;   // Ethernet (el caso de MAWI y CAIDA)
static const uint32_t DLT_RAW     = 101; // IP desnudo
static const uint32_t DLT_RAW_ALT = 12;  // IP desnudo (variante BSD)
static const uint32_t DLT_LINUX_SLL = 113;

static const uint8_t F_SYN       = 1u << 0;
static const uint8_t F_ACK       = 1u << 1;
static const uint8_t F_FIN       = 1u << 2;
static const uint8_t F_RST       = 1u << 3;
static const uint8_t F_SYNTHETIC = 1u << 4;
static const uint8_t F_IPV6      = 1u << 5;

#pragma pack(push, 1)
struct Record {
    uint64_t ts_us;
    uint32_t src;
    uint32_t dst;
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint8_t  proto;
    uint8_t  flags;
};
#pragma pack(pop)

static_assert(sizeof(Record) == 24, "el registro debe ocupar exactamente 24 bytes");

// ------------------------------------------------------------------ utilería

static inline uint16_t bswap16(uint16_t v) { return (uint16_t)((v >> 8) | (v << 8)); }
static inline uint32_t bswap32(uint32_t v) {
    return ((v >> 24) & 0x000000ffu) | ((v >> 8) & 0x0000ff00u) |
           ((v << 8) & 0x00ff0000u) | ((v << 24) & 0xff000000u);
}
static inline uint16_t rd16be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// Pliega una dirección IPv6 de 16 bytes a 32 bits con FNV-1a. Solo se usa con
// --ipv6 hash. Advertencia: esto NO preserva prefijos, así que invalida la
// agregación por /24 o /16 para el tráfico IPv6.
static uint32_t fold_ipv6(const uint8_t *p) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 16; ++i) { h ^= p[i]; h *= 16777619u; }
    return h;
}

struct Stats {
    uint64_t frames = 0, ipv4 = 0, ipv6 = 0, non_ip = 0, truncated = 0;
    uint64_t vlan = 0, frags = 0, out_of_order = 0, written = 0;
    uint64_t bytes = 0;
    uint64_t first_ts = 0, last_ts = 0;
};

// ---------------------------------------------------- parseo de capa de enlace

// Devuelve el desplazamiento del inicio de la cabecera IP y escribe en
// ethertype el tipo de red (0x0800 IPv4, 0x86dd IPv6). Devuelve -1 si el
// paquete no es IP o está demasiado truncado.
static int link_offset(uint32_t dlt, const uint8_t *p, uint32_t caplen,
                       uint16_t *ethertype, Stats *st) {
    switch (dlt) {
    case DLT_EN10MB: {
        if (caplen < 14) return -1;
        uint32_t off = 12;
        uint16_t et = rd16be(p + off);
        off += 2;
        // Desapila etiquetas 802.1Q / 802.1ad. MAWI las trae en varios periodos.
        int guard = 0;
        while ((et == 0x8100 || et == 0x88a8 || et == 0x9100) && guard++ < 4) {
            if (caplen < off + 4) return -1;
            et = rd16be(p + off + 2);
            off += 4;
            st->vlan++;
        }
        if (et == 0x0800 || et == 0x86dd) { *ethertype = et; return (int)off; }
        return -1;
    }
    case DLT_LINUX_SLL: {
        if (caplen < 16) return -1;
        uint16_t et = rd16be(p + 14);
        if (et == 0x0800 || et == 0x86dd) { *ethertype = et; return 16; }
        return -1;
    }
    case DLT_NULL: {
        if (caplen < 4) return -1;
        uint32_t fam = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        if (fam == 2) { *ethertype = 0x0800; return 4; }
        if (fam == 24 || fam == 28 || fam == 30) { *ethertype = 0x86dd; return 4; }
        return -1;
    }
    case DLT_RAW:
    case DLT_RAW_ALT: {
        if (caplen < 1) return -1;
        uint8_t ver = p[0] >> 4;
        if (ver == 4) { *ethertype = 0x0800; return 0; }
        if (ver == 6) { *ethertype = 0x86dd; return 0; }
        return -1;
    }
    default:
        return -1;
    }
}

// ------------------------------------------------------------ programa principal

static void usage(const char *prog) {
    fprintf(stderr,
        "uso: %s [-i entrada.pcap] [-o salida.bin] [opciones]\n"
        "  -i RUTA        archivo pcap de entrada (por defecto stdin)\n"
        "  -o RUTA        archivo binario de salida (por defecto stdout)\n"
        "  --dlt N        forzar el linktype en vez de leerlo de la cabecera\n"
        "  --ipv6 MODO    skip (por defecto) | hash  (hash NO preserva prefijos)\n"
        "  --limit N      procesar a lo más N paquetes\n"
        "  --quiet        no emitir estadísticas por stderr\n"
        "\n"
        "ejemplo: zcat 202501011400.pcap.gz | %s > traza.bin\n",
        prog, prog);
}

int main(int argc, char **argv) {
    const char *in_path = nullptr, *out_path = nullptr;
    bool ipv6_hash = false, quiet = false, force_dlt = false;
    uint32_t dlt_override = 0;
    uint64_t limit = UINT64_MAX;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-i" && i + 1 < argc) in_path = argv[++i];
        else if (a == "-o" && i + 1 < argc) out_path = argv[++i];
        else if (a == "--dlt" && i + 1 < argc) { force_dlt = true; dlt_override = (uint32_t)strtoul(argv[++i], nullptr, 10); }
        else if (a == "--ipv6" && i + 1 < argc) { ipv6_hash = (std::string(argv[++i]) == "hash"); }
        else if (a == "--limit" && i + 1 < argc) limit = strtoull(argv[++i], nullptr, 10);
        else if (a == "--quiet") quiet = true;
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else { fprintf(stderr, "argumento no reconocido: %s\n", argv[i]); usage(argv[0]); return 2; }
    }

    FILE *fin = in_path ? fopen(in_path, "rb") : stdin;
    if (!fin) { perror("fopen entrada"); return 1; }
    FILE *fout = out_path ? fopen(out_path, "wb") : stdout;
    if (!fout) { perror("fopen salida"); return 1; }

    static char inbuf[1 << 20], outbuf[1 << 20];
    setvbuf(fin, inbuf, _IOFBF, sizeof inbuf);
    setvbuf(fout, outbuf, _IOFBF, sizeof outbuf);

    // ---- cabecera global del pcap (24 bytes)
    uint8_t gh[24];
    if (fread(gh, 1, 24, fin) != 24) { fprintf(stderr, "error: entrada demasiado corta\n"); return 1; }

    uint32_t magic_le = (uint32_t)gh[0] | ((uint32_t)gh[1] << 8) |
                        ((uint32_t)gh[2] << 16) | ((uint32_t)gh[3] << 24);
    uint32_t magic_be = bswap32(magic_le);

    bool swap = false, nanos = false;
    if (magic_le == PCAP_MAGIC_US)      { swap = false; nanos = false; }
    else if (magic_le == PCAP_MAGIC_NS) { swap = false; nanos = true;  }
    else if (magic_be == PCAP_MAGIC_US) { swap = true;  nanos = false; }
    else if (magic_be == PCAP_MAGIC_NS) { swap = true;  nanos = true;  }
    else if (magic_le == PCAPNG_MAGIC) {
        fprintf(stderr, "error: el archivo es pcapng, no pcap clásico.\n"
                        "       conviértalo primero:  editcap -F pcap in.pcapng out.pcap\n");
        return 1;
    } else {
        fprintf(stderr, "error: magic 0x%08" PRIx32 " desconocido. ¿Descomprimió el .gz?\n", magic_le);
        return 1;
    }

    uint32_t dlt = (uint32_t)gh[20] | ((uint32_t)gh[21] << 8) |
                   ((uint32_t)gh[22] << 16) | ((uint32_t)gh[23] << 24);
    if (swap) dlt = bswap32(dlt);
    if (force_dlt) dlt = dlt_override;

    if (!quiet)
        fprintf(stderr, "pcap: linktype=%" PRIu32 " %s%s\n", dlt,
                swap ? "(byte-swapped) " : "", nanos ? "(nanosegundos)" : "");

    // ---- bucle de paquetes
    Stats st;
    std::vector<uint8_t> pkt(262144);
    uint8_t ph[16];
    uint64_t prev_ts = 0;

    while (st.frames < limit && fread(ph, 1, 16, fin) == 16) {
        uint32_t ts_sec  = (uint32_t)ph[0]  | ((uint32_t)ph[1] << 8)  | ((uint32_t)ph[2] << 16)  | ((uint32_t)ph[3] << 24);
        uint32_t ts_frac = (uint32_t)ph[4]  | ((uint32_t)ph[5] << 8)  | ((uint32_t)ph[6] << 16)  | ((uint32_t)ph[7] << 24);
        uint32_t caplen  = (uint32_t)ph[8]  | ((uint32_t)ph[9] << 8)  | ((uint32_t)ph[10] << 16) | ((uint32_t)ph[11] << 24);
        uint32_t wirelen = (uint32_t)ph[12] | ((uint32_t)ph[13] << 8) | ((uint32_t)ph[14] << 16) | ((uint32_t)ph[15] << 24);
        if (swap) { ts_sec = bswap32(ts_sec); ts_frac = bswap32(ts_frac);
                    caplen = bswap32(caplen); wirelen = bswap32(wirelen); }

        if (caplen > pkt.size()) {
            if (caplen > (1u << 24)) { fprintf(stderr, "error: caplen absurdo (%u); archivo corrupto\n", caplen); break; }
            pkt.resize(caplen);
        }
        if (fread(pkt.data(), 1, caplen, fin) != caplen) break;

        st.frames++;
        uint64_t ts_us = (uint64_t)ts_sec * 1000000ull + (nanos ? ts_frac / 1000ull : ts_frac);
        if (st.frames == 1) st.first_ts = ts_us;
        st.last_ts = ts_us;
        if (ts_us < prev_ts) st.out_of_order++;
        prev_ts = ts_us;

        uint16_t ethertype = 0;
        int off = link_offset(dlt, pkt.data(), caplen, &ethertype, &st);
        if (off < 0) { st.non_ip++; continue; }

        Record r;
        memset(&r, 0, sizeof r);
        r.ts_us = ts_us;
        r.len = (uint16_t)(wirelen > 65535 ? 65535 : wirelen);

        const uint8_t *ip = pkt.data() + off;
        uint32_t avail = caplen - (uint32_t)off;
        uint32_t l4_off = 0;

        if (ethertype == 0x0800) {                       // ---------------- IPv4
            if (avail < 20) { st.truncated++; continue; }
            uint32_t ihl = (uint32_t)(ip[0] & 0x0f) * 4;
            if (ihl < 20 || avail < ihl) { st.truncated++; continue; }
            r.proto = ip[9];
            r.src = rd32be(ip + 12);
            r.dst = rd32be(ip + 16);
            uint16_t frag = rd16be(ip + 6);
            bool first_frag = (frag & 0x1fff) == 0;      // offset de fragmento 0
            if (!first_frag) st.frags++;
            l4_off = ihl;
            st.ipv4++;
            if (!first_frag) { fwrite(&r, sizeof r, 1, fout); st.written++; st.bytes += r.len; continue; }
        } else {                                          // ---------------- IPv6
            st.ipv6++;
            if (!ipv6_hash) continue;
            if (avail < 40) { st.truncated++; continue; }
            r.flags |= F_IPV6;
            r.proto = ip[6];                              // sin recorrer ext. headers
            r.src = fold_ipv6(ip + 8);
            r.dst = fold_ipv6(ip + 24);
            l4_off = 40;
        }

        if ((r.proto == 6 || r.proto == 17) && avail >= l4_off + 4) {
            const uint8_t *l4 = ip + l4_off;
            r.sport = rd16be(l4);
            r.dport = rd16be(l4 + 2);
            if (r.proto == 6 && avail >= l4_off + 14) {
                uint8_t tf = l4[13];
                if (tf & 0x02) r.flags |= F_SYN;
                if (tf & 0x10) r.flags |= F_ACK;
                if (tf & 0x01) r.flags |= F_FIN;
                if (tf & 0x04) r.flags |= F_RST;
            }
        }

        fwrite(&r, sizeof r, 1, fout);
        st.written++;
        st.bytes += r.len;
    }

    if (fout != stdout) fclose(fout); else fflush(fout);
    if (fin != stdin) fclose(fin);

    if (!quiet) {
        double dur = (st.last_ts > st.first_ts) ? (double)(st.last_ts - st.first_ts) / 1e6 : 0.0;
        fprintf(stderr,
            "----------------------------------------------------------\n"
            "frames leídos      : %" PRIu64 "\n"
            "registros escritos : %" PRIu64 "  (%.1f MB)\n"
            "  IPv4             : %" PRIu64 "\n"
            "  IPv6             : %" PRIu64 " (%s)\n"
            "  no-IP descartados: %" PRIu64 "\n"
            "  truncados        : %" PRIu64 "\n"
            "  fragmentos !=0   : %" PRIu64 "  (sin puertos)\n"
            "  con VLAN         : %" PRIu64 "\n"
            "fuera de orden     : %" PRIu64 "\n"
            "bytes en el cable  : %" PRIu64 "\n"
            "duración           : %.6f s\n"
            "tasa media         : %.0f pkt/s, %.3f Gbps\n"
            "----------------------------------------------------------\n",
            st.frames, st.written, (double)st.written * sizeof(Record) / 1e6,
            st.ipv4, st.ipv6, ipv6_hash ? "plegados a 32 bits" : "descartados",
            st.non_ip, st.truncated, st.frags, st.vlan, st.out_of_order, st.bytes, dur,
            dur > 0 ? st.written / dur : 0.0,
            dur > 0 ? (double)st.bytes * 8.0 / dur / 1e9 : 0.0);
    }
    return 0;
}
