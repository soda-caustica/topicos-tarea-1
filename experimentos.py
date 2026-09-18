import subprocess
import matplotlib.pyplot as plt
from enum import Enum

import pandas as pd


class Ataque(Enum):
    SCAN = ("0", "dst")
    DDOS = ("1", "src")


class Sketch(Enum):
    MIN = "./min_hh"
    SKETCH = "./sketch_hh"


anchos = [256, 1024, 4096]


def correrExperimento(ataque: Ataque, sketch: Sketch, ancho: int, ip: str):
    print(
        f"corriendo experimento, width = {ancho}, ataque = {ataque.name}, sketch = {sketch.name}"
    )
    csv: str = "csv/" + ataque.name + "." + sketch.name + "." + str(ancho) + ".csv"
    _ = subprocess.run(
        [
            sketch.value,
            "trazas/traza.bin",
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
    print(f"calculando csv exacto de {ataque.name}")
    _ = subprocess.run(
        [
            "./exact_hh",
            "trazas/traza.bin",
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


def main():
    for i in Ataque:
        obtenerCsvExacto(i, "192.168.0.1")
        for j in Sketch:
            for k in anchos:
                # TODO: Implementar IP
                correrExperimento(i, j, k, "192.168.0.1")
    for i in Ataque:
        fig, ax = plt.subplots(figsize=(5, 3), layout="constrained")
        csv_exact = pd.read_csv(
            f"csv/query_exacta_{i.name.lower()}.csv",
            usecols=lambda x: x in ["win", "exact_f", "exact_hh"],
        )
        frecuenciasExactas, inicioAtaque, finAtaque = extractExacta(csv_exact)
        t = [x for x in range(inicioAtaque, finAtaque + 1)]
        _ = ax.plot(t, frecuenciasExactas, label="exact")
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
                _ = ax.plot(
                    t, frecuencias, label=f"width = {k}, sketch = {j.value.lower()}"
                )
        fig.savefig(f"{i.name.lower()}.jpg")


def extractAtaque(csv: pd.DataFrame, inicio, fin):
    iterator = csv.itertuples()
    frecuencias = []
    for row in iterator:
        if row.win >= inicio and row.win <= fin:
            frecuencias.append(row.exact_f)

        if row.win > fin:
            break
    return frecuencias


def extractExacta(csv: pd.DataFrame):
    iterator = csv.itertuples()
    frecuencias = []
    inicio, fin = (0, 0)
    previous = None
    attackHappening = False
    for row in iterator:
        if attackHappening:
            frecuencias.append(row.exact_f)
            if row.exact_hh == 0:
                fin = row.win
                break

        previous = row

        if not attackHappening and row.exact_hh == 1:
            attackHappening = True
            frecuencias.append(previous.exact_f)
            frecuencias.append(row.exact_f)
            inicio = previous.win

    return (frecuencias, inicio, fin)


main()
