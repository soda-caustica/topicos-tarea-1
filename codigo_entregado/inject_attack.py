#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
inject_attack.py -- Generador de ataques sintéticos para Tarea 1 2026.

Tópicos en Grandes Volúmenes de Datos.

Toma un archivo de registros de 24 bytes producido por pcap2bin y superpone
un ataque DDoS o scan. Los paquetes inyectados quedan marcados con el bit 4
del campo flags (F_SYNTHETIC) y, opcionalmente, se escribe un JSON con el
ground truth del ataque.

Ejemplos:
  ./inject_attack.py ddos --base traza.bin --out traza_ddos.bin \
      --gt gt_ddos.json --start 300 --duration 30 --pps 50000 --sources 4000

  ./inject_attack.py scan --base traza.bin --out traza_scan.bin \
      --gt gt_scan.json --start 300 --duration 30 --pps 8000 --dst-count 60000

Requisitos: Python 3.8+ y numpy.
Licencia: uso libre para fines docentes.
"""

import argparse
import ipaddress
import json
import os
import sys

import numpy as np

# ---------------------------------------------------------------- formato

REC = np.dtype([
    ("ts",    "<u8"),   # microsegundos desde epoch
    ("src",   "<u4"),   # IPv4 origen
    ("dst",   "<u4"),   # IPv4 destino
    ("sport", "<u2"),
    ("dport", "<u2"),
    ("len",   "<u2"),   # bytes en el cable
    ("proto", "u1"),
    ("flags", "u1"),
])
assert REC.itemsize == 24, "el registro debe ocupar 24 bytes"

F_SYN, F_ACK, F_FIN, F_RST = 0x01, 0x02, 0x04, 0x08
F_SYNTHETIC = 0x10
F_IPV6 = 0x20

PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17

CHUNK = 1 << 20  # registros por bloque al escribir la salida


def ip2int(s):
    return int(ipaddress.IPv4Address(s))


def int2ip(v):
    return str(ipaddress.IPv4Address(int(v)))


# ---------------------------------------------------------- utilidades base

def open_base(path):
    size = os.path.getsize(path)
    if size % REC.itemsize:
        sys.exit("error: %s no es múltiplo de %d bytes; ¿es la salida de pcap2bin?"
                 % (path, REC.itemsize))
    return np.memmap(path, dtype=REC, mode="r")


def sample_top(base, field, sample=2_000_000):
    """Devuelve los valores de `field` ordenados por frecuencia descendente,
    estimados sobre una muestra del comienzo de la traza."""
    n = min(len(base), sample)
    vals, counts = np.unique(np.asarray(base[field][:n]), return_counts=True)
    order = np.argsort(-counts)
    return vals[order], counts[order]


def spread_addresses(prefix, count, rng):
    """`count` direcciones distintas dentro de `prefix`, elegidas al azar."""
    net = ipaddress.IPv4Network(prefix, strict=False)
    space = net.num_addresses
    if count > space:
        sys.exit("error: el prefijo %s solo tiene %d direcciones, se pidieron %d"
                 % (prefix, space, count))
    base_int = int(net.network_address)
    if space <= 1 << 22:
        offs = rng.choice(space, size=count, replace=False)
    else:  # espacio grande: muestreo con rechazo de duplicados
        offs = np.unique(rng.integers(0, space, size=int(count * 1.3)))
        while len(offs) < count:
            offs = np.unique(np.concatenate(
                [offs, rng.integers(0, space, size=count)]))
        offs = rng.permutation(offs)[:count]
    return (base_int + offs).astype("<u4")


def timeline(t0_us, duration_s, pps, rng, jitter=True):
    """Marcas de tiempo del ataque: `pps` paquetes por segundo durante
    `duration_s` segundos, con jitter uniforme dentro de cada intervalo."""
    n = int(round(pps * duration_s))
    if n <= 0:
        sys.exit("error: el ataque no genera ningún paquete (revise --pps y --duration)")
    step = 1_000_000.0 / pps
    ts = t0_us + (np.arange(n, dtype=np.float64) * step)
    if jitter:
        ts += rng.uniform(0.0, step, size=n)
    ts = np.sort(ts.astype(np.uint64))
    return ts


# --------------------------------------------------------------- los ataques

def build_ddos(base, args, rng, t0_us):
    """Inundación distribuida: muchas fuentes falsas contra una víctima.
    Para la tarea, la clave observada es la IP de destino de la víctima."""
    victim = resolve_victim(base, args)
    srcs = spread_addresses(args.src_prefix, args.sources, rng)
    ts = timeline(t0_us, args.duration, args.pps, rng)
    n = len(ts)

    r = np.zeros(n, dtype=REC)
    r["ts"] = ts
    r["src"] = srcs[rng.integers(0, len(srcs), size=n)]
    r["dst"] = victim
    r["sport"] = rng.integers(1024, 65535, size=n).astype("<u2")
    r["dport"] = np.uint16(args.victim_port)
    r["len"] = np.uint16(args.pkt_size)
    r["proto"] = np.uint8(PROTO_TCP)
    r["flags"] = np.uint8(F_SYN | F_SYNTHETIC)

    meta = {
        "tipo": "ddos",
        "victima": int2ip(victim),
        "victima_rango_previo": (args.victim_rank if args.victim == "auto" else None),
        "puerto_victima": args.victim_port,
        "prefijo_origen": args.src_prefix,
        "n_fuentes": int(args.sources),
        "fuentes_ejemplo": [int2ip(v) for v in srcs[:20]],
        "clave_esperada": {
            "por_destino": int2ip(victim),
            "por_prefijo_origen_24": "no concentrado; use /16 o el destino",
        },
    }
    return r, meta


def build_scan(base, args, rng, t0_us):
    """Escaneo horizontal: una fuente toca muchísimos destinos en un puerto.
    Para la tarea, la clave observada es la IP de origen del atacante."""
    attacker = ip2int(args.attacker)
    ts = timeline(t0_us, args.duration, args.pps, rng)
    n = len(ts)
    dsts = spread_addresses(args.dst_prefix, args.dst_count, rng)

    r = np.zeros(n, dtype=REC)
    r["ts"] = ts
    r["src"] = np.uint32(attacker)
    r["dst"] = dsts[rng.integers(0, len(dsts), size=n)]
    r["sport"] = rng.integers(40000, 60000, size=n).astype("<u2")
    r["dport"] = np.uint16(args.victim_port)
    r["len"] = np.uint16(args.pkt_size)
    r["proto"] = np.uint8(PROTO_TCP)
    r["flags"] = np.uint8(F_SYN | F_SYNTHETIC)

    meta = {
        "tipo": "scan",
        "atacante": args.attacker,
        "prefijo_destino": args.dst_prefix,
        "n_destinos": int(args.dst_count),
        "puerto": args.victim_port,
        "clave_esperada": {"por_origen": args.attacker},
    }
    return r, meta


def resolve_victim(base, args):
    """Elige la víctima. En modo automático NO se toma el destino más frecuente:
    ese ya puede ser heavy hitter por sí solo y la latencia de detección
    quedaría en cero. Se toma un destino de ranking intermedio que existe en la
    traza pero que, normalmente, no satisface el umbral antes del ataque."""
    if args.victim != "auto":
        return ip2int(args.victim)
    vals, counts = sample_top(base, "dst", sample=2_000_000)
    r = min(args.victim_rank, len(vals) - 1)
    if r < 10:
        sys.stderr.write("aviso: --victim-rank %d elige un destino que ya está en "
                         "el top-10; el ataque no lo hara subir\n" % r)
    sys.stderr.write("victima automatica: rango %d en la muestra, %d paquetes previos\n"
                     % (r, int(counts[r])))
    return int(vals[r])


BUILDERS = {"ddos": build_ddos, "scan": build_scan}


# ------------------------------------------------------------------ mezcla

def merge_write(base, atk, out_path):
    """Mezcla por marca de tiempo en bloques de tamaño acotado. Ambas
    secuencias ya están ordenadas, así que basta un searchsorted."""
    nb, na = len(base), len(atk)
    idx = np.searchsorted(np.asarray(base["ts"]), atk["ts"], side="right")
    atk_pos = idx + np.arange(na, dtype=np.int64)   # posición final de cada ataque
    total = nb + na

    bi = 0
    ai = 0
    with open(out_path, "wb") as fo:
        for start in range(0, total, CHUNK):
            end = min(start + CHUNK, total)
            hi = ai
            while hi < na and atk_pos[hi] < end:
                hi += 1
            k = hi - ai                       # ataques en este bloque
            m = (end - start) - k             # registros de base en este bloque
            buf = np.empty(end - start, dtype=REC)
            if k:
                buf[atk_pos[ai:hi] - start] = atk[ai:hi]
                mask = np.ones(end - start, dtype=bool)
                mask[atk_pos[ai:hi] - start] = False
                buf[mask] = base[bi:bi + m]
            else:
                buf[:] = base[bi:bi + m]
            fo.write(buf.tobytes())
            bi += m
            ai = hi
    assert bi == nb and ai == na, "la mezcla no consumió todas las entradas"
    return total


# -------------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(
        description="Superpone ataques sintéticos sobre una traza binaria de 24 B/registro.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("tipo", choices=sorted(BUILDERS), help="tipo de ataque a inyectar")
    p.add_argument("--base", required=True, help="traza de entrada (.bin de pcap2bin)")
    p.add_argument("--out", required=True, help="traza de salida con el ataque")
    p.add_argument("--gt", help="archivo JSON con el ground truth del ataque")

    p.add_argument("--start", type=float, default=60.0,
                   help="inicio del ataque, en segundos desde el primer paquete (def. 60)")
    p.add_argument("--duration", type=float, default=30.0,
                   help="duración del ataque en segundos (def. 30)")
    p.add_argument("--pps", type=float, default=50000.0,
                   help="paquetes por segundo del ataque (def. 50000)")
    p.add_argument("--pkt-size", type=int, default=64,
                   help="bytes en el cable por paquete inyectado (def. 64)")
    p.add_argument("--seed", type=int, default=42, help="semilla del generador (def. 42)")

    p.add_argument("--victim", default="auto",
                   help="IP víctima, o 'auto' para elegir un destino de ranking intermedio")
    p.add_argument("--victim-port", type=int, default=80)
    p.add_argument("--victim-rank", type=int, default=1000,
                   help="con --victim auto, ranking del destino elegido (def. 1000). "
                        "Se usa un ranking intermedio para evitar que la víctima sea HH antes del ataque")
    p.add_argument("--attacker", default="198.18.0.7", help="IP atacante (scan)")

    p.add_argument("--sources", type=int, default=4000, help="fuentes falsas (ddos)")
    p.add_argument("--src-prefix", default="198.18.0.0/16",
                   help="prefijo del que salen las fuentes falsas (ddos)")
    p.add_argument("--dst-count", type=int, default=60000, help="destinos barridos (scan)")
    p.add_argument("--dst-prefix", default="198.18.0.0/16", help="prefijo barrido (scan)")

    args = p.parse_args()
    rng = np.random.default_rng(args.seed)

    base = open_base(args.base)
    if len(base) == 0:
        sys.exit("error: la traza base está vacía")

    t_first = int(base["ts"][0])
    t_last = int(base["ts"][-1])
    span = (t_last - t_first) / 1e6
    t0_us = t_first + int(args.start * 1_000_000)
    if args.start < 0 or args.start + args.duration > span:
        sys.exit("error: el intervalo [%.1f, %.1f] s no cabe en la traza, que dura %.3f s"
                 % (args.start, args.start + args.duration, span))

    atk, meta = BUILDERS[args.tipo](base, args, rng, t0_us)
    total = merge_write(base, atk, args.out)

    # ---- ground truth
    secs = ((atk["ts"] - t0_us) // 1_000_000).astype(np.int64)
    per_sec = np.bincount(secs, minlength=int(np.ceil(args.duration))).tolist()
    gt = {
        "traza_base": os.path.abspath(args.base),
        "traza_salida": os.path.abspath(args.out),
        "semilla": args.seed,
        "ventana_ataque_us": [int(t0_us), int(atk["ts"][-1])],
        "ventana_ataque_rel_s": [args.start, args.start + args.duration],
        "paquetes_inyectados": int(len(atk)),
        "bytes_inyectados": int(atk["len"].astype(np.int64).sum()),
        "pps_nominal": args.pps,
        "paquetes_por_segundo_reales": per_sec,
        "registros_base": int(len(base)),
        "registros_salida": int(total),
        "fraccion_sintetica": round(len(atk) / total, 6),
        "marca": "bit 4 de flags (0x10) en cada paquete inyectado",
        "ataque": meta,
    }
    if args.gt:
        with open(args.gt, "w", encoding="utf-8") as f:
            json.dump(gt, f, indent=2, ensure_ascii=False)

    sys.stderr.write(
        "--------------------------------------------------------\n"
        "ataque             : %s\n"
        "traza base         : %d registros, %.3f s\n"
        "inyectados         : %d paquetes (%.4f%% del total), %.2f MB\n"
        "intervalo          : [%.2f, %.2f] s desde el inicio\n"
        "salida             : %s (%d registros)\n"
        "ground truth       : %s\n"
        "--------------------------------------------------------\n"
        % (args.tipo, len(base), span, len(atk), 100.0 * len(atk) / total,
           gt["bytes_inyectados"] / 1e6, args.start, args.start + args.duration,
           args.out, total, args.gt or "(no solicitado)"))


if __name__ == "__main__":
    main()
