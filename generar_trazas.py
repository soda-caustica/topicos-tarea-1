#!/usr/bin/env python3
"""Genera trazas DDoS y scan reproducibles desde una traza PCAP o BIN."""

import argparse
import gzip
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
INJECTOR = ROOT / "codigo_entregado" / "inject_attack.py"


def convertir_traza(trace_path: Path, binary_path: Path, pcap2bin: Path) -> Path:
    if trace_path.suffix.lower() == ".bin":
        return trace_path

    binary_path.parent.mkdir(parents=True, exist_ok=True)
    command = [str(pcap2bin), "-o", str(binary_path)]
    if trace_path.suffix.lower() == ".gz":
        with gzip.open(trace_path, "rb") as source:
            subprocess.run(command, stdin=source, check=True)
    else:
        command.extend(["-i", str(trace_path)])
        subprocess.run(command, check=True)
    return binary_path


def generar_ataque(tipo: str, base: Path, trace_out: Path, gt_out: Path,
                   args: argparse.Namespace, pps: int) -> dict:
    command = [
        sys.executable,
        str(INJECTOR),
        tipo,
        "--base", str(base),
        "--out", str(trace_out),
        "--gt", str(gt_out),
        "--seed", str(args.seed),
        "--start", str(args.start),
        "--duration", str(args.duration),
        "--pps", str(pps),
    ]
    if tipo == "ddos":
        command.extend(["--sources", str(args.sources)])
    else:
        command.extend(["--attacker", args.attacker, "--dst-count", str(args.dst_count)])

    subprocess.run(command, check=True)
    with gt_out.open(encoding="utf-8") as gt_file:
        return json.load(gt_file)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Convierte una traza si hace falta, genera DDoS y scan, y extrae sus IPs."
    )
    parser.add_argument("traza", type=Path, help="archivo .pcap, .pcap.gz o BIN de pcap2bin")
    parser.add_argument("--seed", type=int, required=True, help="semilla reproducible")
    parser.add_argument("--out-dir", type=Path, default=ROOT,
                        help="directorio base de salida (por defecto: raíz del proyecto)")
    parser.add_argument("--pcap2bin", type=Path, default=ROOT / "pcap2bin",
                        help="ruta al conversor pcap2bin")
    parser.add_argument("--start", type=float, default=300.0,
                        help="inicio del ataque en segundos (defecto: 300)")
    parser.add_argument("--duration", type=float, default=30.0,
                        help="duración de cada ataque en segundos (defecto: 30)")
    parser.add_argument("--ddos-pps", type=int, default=50000,
                        help="paquetes por segundo del DDoS")
    parser.add_argument("--scan-pps", type=int, default=8000,
                        help="paquetes por segundo del scan")
    parser.add_argument("--sources", type=int, default=4000,
                        help="número de fuentes del DDoS")
    parser.add_argument("--dst-count", type=int, default=60000,
                        help="número de destinos del scan")
    parser.add_argument("--attacker", default="198.18.0.7", help="IP origen del scan")
    args = parser.parse_args(argv)

    trace_path = args.traza.resolve()
    if not trace_path.is_file():
        parser.error(f"no existe la traza: {trace_path}")
    if not INJECTOR.is_file():
        parser.error(f"no se encontró el generador: {INJECTOR}")

    out_dir = args.out_dir.resolve()
    traces_dir = out_dir / "trazas"
    traces_dir.mkdir(parents=True, exist_ok=True)
    base = convertir_traza(trace_path, traces_dir / "traza.bin", args.pcap2bin.resolve())

    ground_truth = {}
    for tipo, pps in (("ddos", args.ddos_pps), ("scan", args.scan_pps)):
        ground_truth[tipo] = generar_ataque(
            tipo,
            base,
            traces_dir / f"traza_{tipo}.bin",
            out_dir / f"gt_{tipo}.json",
            args,
            pps,
        )

    ips = {
        "semilla": args.seed,
        "scan": ground_truth["scan"]["ataque"]["atacante"],
        "ddos": ground_truth["ddos"]["ataque"]["victima"],
    }
    ips_path = out_dir / "ips_ataques.json"
    with ips_path.open("w", encoding="utf-8") as ips_file:
        json.dump(ips, ips_file, indent=2, ensure_ascii=False)
        ips_file.write("\n")

    print(f"Traza DDoS: {traces_dir / 'traza_ddos.bin'}")
    print(f"Traza scan: {traces_dir / 'traza_scan.bin'}")
    print(f"IP scan (origen): {ips['scan']}")
    print(f"IP DDoS (víctima): {ips['ddos']}")
    print(f"IPs guardadas en: {ips_path}")


if __name__ == "__main__":
    main()