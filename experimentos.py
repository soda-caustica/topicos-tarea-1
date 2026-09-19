import os
import subprocess
import sys
from enum import Enum

import matplotlib.pyplot as plt
import pandas as pd


class Ataque(Enum):
    # En scan, el atacante es la IP origen; en ddos, la víctima es la IP destino.
    SCAN = ("0", "src")
    DDOS = ("1", "dst")


class Sketch(Enum):
    MIN = "./min_hh"
    SKETCH = "./sketch_hh"


DEFAULT_SCAN_IP = "198.18.0.7"
DEFAULT_DDOS_IP = "222.160.209.129"
anchos = [256, 1024, 4096]


def correrExperimento(ataque: Ataque, sketch: Sketch, ancho: int, ip: str):
    print(
        f"corriendo experimento, width = {ancho}, ataque = {ataque.name}, sketch = {sketch.name}"
    )
    csv: str = "csv/" + ataque.name + "." + sketch.name + "." + str(ancho) + ".csv"
    _ = subprocess.run(
        [
            sketch.value,
            f"trazas/traza_{ataque.name.lower()}.bin",
            ip,
            "5",
            str(ancho),
            ataque.value[0],
            f"csv/query_exacta_{ataque.name.lower()}.csv",
            csv,
        ],
        check=True,
    )


def obtenerCsvExacto(ataque: Ataque, ip: str):
    trace_path = f"trazas/traza_{ataque.name.lower()}.bin"
    if not os.path.exists(trace_path):
        raise FileNotFoundError(f"No existe la traza de ataque esperada: {trace_path}")

    print(f"calculando csv exacto de {ataque.name} sobre {trace_path}")
    _ = subprocess.run(
        [
            "./exact_hh",
            trace_path,
            "--key",
            ataque.value[1],
            "-W",
            "60",
            "--delta",
            "10",
            "--phi",
            "0.01",
            "--query",
            ip,
            "--out-query",
            f"csv/query_exacta_{ataque.name.lower()}.csv",
        ],
        check=True,
    )


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 0:
        scan_ip = DEFAULT_SCAN_IP
        ddos_ip = DEFAULT_DDOS_IP
    elif len(args) == 2:
        scan_ip, ddos_ip = args
    else:
        raise SystemExit("Uso: python3 experimentos.py [scan_ip] [ddos_ip]")

    ips = {
        Ataque.SCAN: scan_ip,
        Ataque.DDOS: ddos_ip,
    }

    for i in Ataque:
        obtenerCsvExacto(i, ips[i])
        for j in Sketch:
            for k in anchos:
                correrExperimento(i, j, k, ips[i])

    colores = {256: "#d95f02", 1024: "#1b9e77", 4096: "#7570b3"}
    estilos = {Sketch.MIN: "-", Sketch.SKETCH: "--"}

    for i in Ataque:
        fig, ax = plt.subplots(figsize=(8, 4.5), layout="constrained")
        csv_exact = pd.read_csv(
            f"csv/query_exacta_{i.name.lower()}.csv",
            usecols=lambda x: x in ["win", "exact_f", "exact_hh"],
        )
        frecuenciasExactas, inicioAtaque, finAtaque = extractExacta(csv_exact)
        if not frecuenciasExactas:
            print(
                f"saltando {i.name}: no se detectó ninguna ventana de ataque para {ips[i]}"
            )
            plt.close(fig)
            continue

        t = [x for x in range(inicioAtaque, finAtaque + 1)]
        _ = ax.plot(
            t,
            frecuenciasExactas,
            color="#222222",
            linewidth=2.5,
            marker="o",
            markersize=4,
            label="Exacto",
            zorder=3,
        )
        for j in Sketch:
            for k in anchos:  # win,tau_us,t_rel_s,key,N,threshold,estimate_f,estimate_hh,estimate_delta,matches_exact_n,abs_err,rel_err
                csv = pd.read_csv(
                    f"csv/{i.name}.{j.name}.{k}.csv",
                    usecols=lambda x: (
                        x
                        in [
                            "win",
                            "estimate_f",
                            "estimate_hh",
                            "matches_exact_n",
                            "rel_err",
                        ]
                    ),
                )
                frecuencias = extractAtaque(csv, inicioAtaque, finAtaque)
                if len(frecuencias) == len(t):
                    _ = ax.plot(
                        t,
                        frecuencias,
                        color=colores[k],
                        linestyle=estilos[j],
                        linewidth=1.8,
                        marker=".",
                        markersize=5,
                        label=f"{j.name} - width {k}",
                    )
                else:
                    print(
                        f"saltando {i.name}/{j.name}/w={k}: longitudes incompatibles "
                        f"({len(frecuencias)} vs {len(t)})"
                    )
        ax.legend()
        ax.set_title(f"Frecuencia estimada - {i.name}", fontsize=14, pad=12)
        ax.set_xlabel("Ventana")
        ax.set_ylabel("Frecuencia")
        ax.set_xticks(t)
        ax.grid(axis="y", linestyle=":", linewidth=0.8, alpha=0.65)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.legend(
            loc="upper left",
            bbox_to_anchor=(1.02, 1),
            borderaxespad=0,
            frameon=False,
            title="Metodo y ancho",
        )
        fig.savefig(f"{i.name.lower()}.jpg", dpi=160, bbox_inches="tight")
        plt.close(fig)


def extractAtaque(csv: pd.DataFrame, inicio, fin):
    iterator = csv.itertuples()
    frecuencias = []
    for row in iterator:
        if row.win >= inicio and row.win <= fin:
            frecuencias.append(row.estimate_f)

        if row.win > fin:
            break
    return frecuencias


def extractExacta(csv: pd.DataFrame):
    rows = csv.to_dict("records")
    start_idx = None
    end_idx = None

    for i, row in enumerate(rows):
        if row["exact_hh"] == 1 and start_idx is None:
            start_idx = i
        elif start_idx is not None and row["exact_hh"] == 0:
            end_idx = i - 1
            break

    if start_idx is None:
        return ([], 0, 0)

    if end_idx is None:
        end_idx = len(rows) - 1

    # Incluye una ventana de contexto antes y otra después del ataque.
    start_idx = max(0, start_idx - 1)
    end_idx = min(len(rows) - 1, end_idx + 1)
    window_rows = rows[start_idx : end_idx + 1]
    frecuencias = [row["exact_f"] for row in window_rows]
    inicio = window_rows[0]["win"]
    fin = window_rows[-1]["win"]
    return (frecuencias, inicio, fin)


if __name__ == "__main__":
    main()
