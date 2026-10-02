import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from enum import Enum

# Asegurar acceso a paquetes de usuario si están en ~/.local
user_site = "/home/maxi/.local/lib/python3.14/site-packages"
if os.path.exists(user_site) and user_site not in sys.path:
    sys.path.insert(0, user_site)

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
CLEAN_TRACE_IP = "203.143.43.244" # Emisor / destino heavy hitter de la traza base
anchos = [256, 1024, 4096]
d_depth = 5
default_seed = 42


def correrExperimento(ataque: Ataque, sketch: Sketch, ancho: int, ip: str, seed: int = default_seed):
    print(
        f"corriendo experimento: width={ancho}, ataque={ataque.name}, sketch={sketch.name}"
    )
    csv_out: str = f"csv/{ataque.name}.{sketch.name}.{ancho}.csv"
    trace_path = f"trazas/traza_{ataque.name.lower()}.bin"
    exact_csv = f"csv/query_exacta_{ataque.name.lower()}.csv"

    subprocess.run(
        [
            sketch.value,
            trace_path,
            ip,
            str(d_depth),
            str(ancho),
            ataque.value[0],
            exact_csv,
            csv_out,
            str(seed),
        ],
        check=True,
    )


def obtenerCsvExacto(ataque: Ataque, ip: str):
    trace_path = f"trazas/traza_{ataque.name.lower()}.bin"
    if not os.path.exists(trace_path):
        raise FileNotFoundError(f"No existe la traza de ataque esperada: {trace_path}")

    out_exact = f"csv/query_exacta_{ataque.name.lower()}.csv"
    print(f"calculando csv exacto de {ataque.name} sobre {trace_path}")
    subprocess.run(
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
            out_exact,
        ],
        check=True,
    )


def validarTrazaLimpia(ip: str = CLEAN_TRACE_IP):
    clean_trace = "trazas/traza.bin"
    if not os.path.exists(clean_trace):
        print(f"Aviso: {clean_trace} no encontrada, omitiendo validación limpia.")
        return []

    print(f"\n=== Validando Traza Limpia Sin Ataques ({clean_trace}) para IP {ip} ===")
    exact_clean_csv = "csv/query_exacta_clean.csv"
    subprocess.run(
        [
            "./exact_hh",
            clean_trace,
            "--key",
            "src",
            "-W",
            "60",
            "--delta",
            "10",
            "--phi",
            "0.01",
            "--query",
            ip,
            "--out-query",
            exact_clean_csv,
        ],
        check=True,
    )

    resultados_clean = []
    for sk in Sketch:
        for w in anchos:
            out_csv = f"csv/CLEAN.{sk.name}.{w}.csv"
            subprocess.run(
                [
                    sk.value,
                    clean_trace,
                    ip,
                    str(d_depth),
                    str(w),
                    "0", # src
                    exact_clean_csv,
                    out_csv,
                    str(default_seed),
                ],
                check=True,
            )
            df = pd.read_csv(out_csv)
            if not (df["matches_exact_window"] == 1).all():
                raise ValueError(f"Ventanas desalineadas en traza limpia para {sk.name}/w={w}")
            if not (df["matches_exact_n"] == 1).all():
                raise ValueError(f"N no coincide con exact_hh en traza limpia para {sk.name}/w={w}")
            if not (df["matches_exact_hh"] == 1).all():
                raise ValueError(f"Decisión HH distinta en traza limpia para {sk.name}/w={w}")
            # Calcular error sobre ventanas con f > 0
            df_valid = df[df["rel_err"] >= 0]
            avg_abs_err = df_valid["abs_err"].mean()
            avg_rel_err = df_valid["rel_err"].mean()
            mem_bytes = (6 + 2) * d_depth * w * 4 + 6 * 8
            resultados_clean.append({
                "Escenario": "Traza limpia (src)",
                "Sketch": "CMS" if sk == Sketch.MIN else "CountSketch",
                "Width": w,
                "Memoria (KB)": round(mem_bytes / 1024.0, 2),
                "Error Absoluto Medio": round(avg_abs_err, 2),
                "MRE (%)": round(avg_rel_err * 100.0, 4),
            })
    return resultados_clean


def extractExacta(csv_exact: pd.DataFrame, ataque: Ataque):
    with open(f"gt_{ataque.name.lower()}.json", encoding="utf-8") as gt_file:
        ground_truth = json.load(gt_file)

    attack_start_us, attack_end_us = ground_truth["ventana_ataque_us"]
    rows = csv_exact.to_dict("records")
    context_rows = [
        row for row in rows
        if attack_start_us - 60_000_000 <= row["tau_us"] <= attack_end_us + 60_000_000 + 1_000_000
    ]
    if not context_rows:
        return ([], 0, 0, [], attack_start_us, attack_end_us)

    # J covers positive-frequency windows while injected packets remain in the active window.
    j_rows = [
        row["win"] for row in rows
        if row["tau_us"] > attack_start_us
        and row["tau_us"] - 60_000_000 < attack_end_us
        and row["exact_f"] > 0
    ]

    frecuencias = [row["exact_f"] for row in context_rows]
    inicio_win = context_rows[0]["win"]
    fin_win = context_rows[-1]["win"]
    return (frecuencias, inicio_win, fin_win, j_rows, attack_start_us, attack_end_us)


def graficarFrecuencias(ataque: Ataque, inicio_win: int, fin_win: int,
                        attack_start_us: int, attack_end_us: int):
    exact_df = pd.read_csv(f"csv/query_exacta_{ataque.name.lower()}.csv")
    exact_context = exact_df[(exact_df["win"] >= inicio_win) & (exact_df["win"] <= fin_win)]
    t = ((exact_context["tau_us"] - attack_start_us) / 1e6).tolist()
    frecuenciasExactas = exact_context["exact_f"].tolist()
    attack_duration_s = round((attack_end_us - attack_start_us) / 1e6)
    attack_color = "#b2182b"
    colores = {256: "#d95f02", 1024: "#1b9e77", 4096: "#7570b3"}
    estilos = {Sketch.MIN: "-", Sketch.SKETCH: "--"}

    fig, ax = plt.subplots(figsize=(9, 5), layout="constrained")
    ax.plot(
        t,
        frecuenciasExactas,
        color="#111111",
        linewidth=2.8,
        marker="o",
        markersize=4,
        label="Exacto",
        zorder=2,
    )

    for j in Sketch:
        for k in anchos:
            csv_path = f"csv/{ataque.name}.{j.name}.{k}.csv"
            df = pd.read_csv(csv_path)
            sub = df[(df["win"] >= inicio_win) & (df["win"] <= fin_win)]
            frecuencias = sub["estimate_f"].tolist()
            if len(frecuencias) == len(t):
                sk_label = "CMS" if j == Sketch.MIN else "CS"
                ax.plot(
                    t,
                    frecuencias,
                    color=colores[k],
                    linestyle=estilos[j],
                    linewidth=1.8,
                    marker=".",
                    markersize=4,
                    label=f"{sk_label} (w={k})",
                    alpha=0.85,
                    zorder=3,
                )

    for boundary in (0, attack_duration_s):
        ax.axvline(boundary, color=attack_color, linestyle="--", linewidth=1.2, alpha=0.8)
    ax.text(0, 0.98, "Inicio", transform=ax.get_xaxis_transform(), color=attack_color,
            fontsize=8, ha="left", va="top", bbox={"facecolor": "white", "alpha": 0.8, "edgecolor": "none", "pad": 1})
    ax.text(attack_duration_s, 0.98, "Fin", transform=ax.get_xaxis_transform(), color=attack_color,
            fontsize=8, ha="right", va="top", bbox={"facecolor": "white", "alpha": 0.8, "edgecolor": "none", "pad": 1})
    context_end_s = attack_duration_s + 60
    ax.set_xticks(sorted(set(ax.get_xticks()) | {-60, context_end_s}))
    ax.set_xlim(-60, max(context_end_s, max(t)) + 0.5)
    ax.set_title(f"Frecuencia exacta y estimada: {ataque.name}", fontsize=13, pad=12)
    ax.set_xlabel("Tiempo relativo al inicio del ataque (s)", fontsize=11)
    ax.set_ylabel("Frecuencia (paquetes)", fontsize=11)
    ax.grid(axis="y", linestyle=":", linewidth=0.8, alpha=0.65)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(
        loc="upper left",
        bbox_to_anchor=(1.02, 1),
        borderaxespad=0,
        frameon=False,
        title="Estimador y ancho",
    )
    out_img = f"{ataque.name.lower()}.jpg"
    fig.savefig(out_img, dpi=180, bbox_inches="tight")
    plt.close(fig)
    print(f"Gráfico de frecuencias guardado: {out_img}")


def graficarDelta(ataque: Ataque, inicio_win: int, fin_win: int,
                  csv_exact: pd.DataFrame, attack_start_us: int, attack_end_us: int):
    sub_exact = csv_exact[(csv_exact["win"] >= inicio_win) & (csv_exact["win"] <= fin_win)]
    t = ((sub_exact["tau_us"] - attack_start_us) / 1e6).tolist()
    deltas_exactas = sub_exact["exact_delta"].fillna(0).tolist()
    attack_duration_s = round((attack_end_us - attack_start_us) / 1e6)
    attack_color = "#b2182b"

    colores = {256: "#d95f02", 1024: "#1b9e77", 4096: "#7570b3"}
    estilos = {Sketch.MIN: "-", Sketch.SKETCH: "--"}

    fig, (ax, ax_resid) = plt.subplots(
        2, 1, figsize=(9, 7), sharex=True, layout="constrained",
        gridspec_kw={"height_ratios": [2, 1]},
    )
    fig.suptitle(f"Cambio de frecuencia Δf: {ataque.name}", fontsize=13)
    ax.plot(
        t,
        deltas_exactas,
        color="#111111",
        linewidth=2.0,
        marker="s",
        markersize=3,
        label="Exacto Δf",
        zorder=5,
    )

    for j in Sketch:
        for k in anchos:
            csv_path = f"csv/{ataque.name}.{j.name}.{k}.csv"
            df = pd.read_csv(csv_path)
            sub = df[(df["win"] >= inicio_win) & (df["win"] <= fin_win)]
            deltas = sub["estimate_delta"].tolist()
            if len(deltas) == len(t):
                sk_label = "CMS-med" if j == Sketch.MIN else "CS"
                label = f"{sk_label} (w={k})"
                ax.plot(
                    t,
                    deltas,
                    color=colores[k],
                    linestyle=estilos[j],
                    linewidth=1.4,
                    marker=".",
                    markersize=5,
                    label=label,
                    alpha=0.95,
                    zorder=3,
                )
                ax_resid.plot(
                    t,
                    [estimate - exact for estimate, exact in zip(deltas, deltas_exactas)],
                    color=colores[k],
                    linestyle=estilos[j],
                    linewidth=1.4,
                    marker=".",
                    markersize=4,
                    label=label,
                    alpha=0.95,
                )

    for axis in (ax, ax_resid):
        for boundary in (0, attack_duration_s):
            axis.axvline(boundary, color=attack_color, linestyle="--", linewidth=1.2, alpha=0.8)
        context_end_s = attack_duration_s + 60
        axis.set_xticks(sorted(set(axis.get_xticks()) | {-60, context_end_s}))
        axis.set_xlim(-60, max(context_end_s, max(t)) + 0.5)
        ax.text(0, 0.98, "Inicio", transform=ax.get_xaxis_transform(), color=attack_color,
            fontsize=8, ha="left", va="top", bbox={"facecolor": "white", "alpha": 0.8, "edgecolor": "none", "pad": 1})
        ax.text(attack_duration_s, 0.98, "Fin", transform=ax.get_xaxis_transform(), color=attack_color,
            fontsize=8, ha="right", va="top", bbox={"facecolor": "white", "alpha": 0.8, "edgecolor": "none", "pad": 1})
    ax.set_ylabel("Δf (paquetes)", fontsize=10)
    ax_resid.axhline(0, color="#111111", linestyle=":", linewidth=1)
    ax_resid.set_xlabel("Tiempo relativo al inicio del ataque (s)", fontsize=10)
    ax_resid.set_ylabel("Estimado − exacto", fontsize=9)
    for axis in (ax, ax_resid):
        axis.grid(axis="y", linestyle=":", linewidth=0.8, alpha=0.65)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
    ax.legend(
        loc="upper left",
        bbox_to_anchor=(1.02, 1),
        borderaxespad=0,
        frameon=False,
        title="Estimador y ancho",
    )
    out_img = f"{ataque.name.lower()}_delta.jpg"
    fig.savefig(out_img, dpi=180, bbox_inches="tight")
    plt.close(fig)
    print(f"Gráfico de delta guardado: {out_img}")


def calcularMetricas(ataque: Ataque, j_wins: list, attack_start_us: int,
                     inicio_win: int, fin_win: int):
    exact_df = pd.read_csv(f"csv/query_exacta_{ataque.name.lower()}.csv")
    
    # Primera ventana con detección exacta
    exact_hh_rows = exact_df[exact_df["exact_hh"] == 1]
    first_exact_win = exact_hh_rows["win"].iloc[0] if not exact_hh_rows.empty else None
    first_exact_tau = exact_hh_rows["tau_us"].iloc[0] if not exact_hh_rows.empty else None

    metricas_ataque = []

    for sk in Sketch:
        for w in anchos:
            csv_path = f"csv/{ataque.name}.{sk.name}.{w}.csv"
            df = pd.read_csv(csv_path)

            # 1. MRE sobre conjunto J (Sección 6.2.2)
            df_j = df[df["win"].isin(j_wins)]
            if df_j.empty or not (df_j["exact_f"] > 0).all():
                raise ValueError(f"J no contiene frecuencias exactas positivas para {ataque.name}/{sk.name}/w={w}")
            mre = df_j["rel_err"].mean()

            if not (df["matches_exact_window"] == 1).all():
                raise ValueError(f"Ventanas desalineadas para {ataque.name}/{sk.name}/w={w}")
            if not (df["matches_exact_n"] == 1).all():
                raise ValueError(f"N no coincide con exact_hh para {ataque.name}/{sk.name}/w={w}")
            hh_disagreements = int((df["matches_exact_hh"] == 0).sum())

            exact_delta = exact_df[["win", "exact_delta"]].rename(
                columns={"exact_delta": "reference_delta"}
            )
            df_context = df[(df["win"] >= inicio_win) & (df["win"] <= fin_win)].merge(
                exact_delta, on="win", how="inner", validate="one_to_one"
            )
            if not (df_context["exact_delta"] == df_context["reference_delta"]).all():
                raise ValueError(f"Delta exacto no coincide con la referencia para {ataque.name}/{sk.name}/w={w}")
            delta_mae = (df_context["estimate_delta"] - df_context["reference_delta"]).abs().mean()

            # 2. Latencia de detección (Sección 6.2.3)
            det_rows = df[df["estimate_hh"] == 1]
            if not det_rows.empty:
                first_det_win = det_rows["win"].iloc[0]
                first_det_tau = det_rows["tau_us"].iloc[0]
                latencia_s = (first_det_tau - attack_start_us) / 1e6
                status_det = "Misma ventana" if first_det_win == first_exact_win else (
                    "Falso Positivo temprano" if first_det_win < first_exact_win else "Retardo"
                )
            else:
                first_det_win = None
                latencia_s = None
                status_det = "No detectado"

            # 3. Memoria contadores
            mem_bytes = (6 + 2) * d_depth * w * 4 + 6 * 8

            # 4. Deltas: mayor incremento y decremento
            max_inc = df_context["estimate_delta"].max()
            min_dec = df_context["estimate_delta"].min()
            exact_max_inc = df_context["reference_delta"].max()
            exact_min_dec = df_context["reference_delta"].min()

            sk_name = "CMS" if sk == Sketch.MIN else "CountSketch"
            metricas_ataque.append({
                "Ataque": ataque.name,
                "Sketch": sk_name,
                "Width": w,
                "Memoria (KB)": round(mem_bytes / 1024.0, 2),
                "MRE (%)": round(mre * 100.0, 4),
                "Desacuerdos HH": hh_disagreements,
                "MAE Δf (contexto)": round(delta_mae, 2),
                "Win Detectada": first_det_win,
                "Latencia (s)": latencia_s,
                "Estado Deteccion": status_det,
                "Max Inc Δf": max_inc,
                "Max Dec Δf": min_dec,
                "Max Inc Δ exacto": exact_max_inc,
                "Max Dec Δ exacto": exact_min_dec,
            })

    return metricas_ataque


def to_markdown_table(df: pd.DataFrame) -> str:
    headers = list(df.columns)
    lines = []
    lines.append("| " + " | ".join(str(h) for h in headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for _, row in df.iterrows():
        lines.append("| " + " | ".join(str(val) for val in row) + " |")
    return "\n".join(lines)


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

    # 1. Generar CSV exactos
    with ThreadPoolExecutor(max_workers=len(Ataque)) as executor:
        futuros = [executor.submit(obtenerCsvExacto, ataque, ips[ataque]) for ataque in Ataque]
        for futuro in futuros:
            futuro.result()

    # 2. Correr experimentos con sketches
    trabajos = [
        (ataque, sketch, ancho, ips[ataque])
        for ataque in Ataque
        for sketch in Sketch
        for ancho in anchos
    ]
    with ThreadPoolExecutor(max_workers=min(len(trabajos), 6)) as executor:
        futuros = [executor.submit(correrExperimento, *trabajo) for trabajo in trabajos]
        for futuro in futuros:
            futuro.result()

    todas_las_metricas = []

    # 3. Graficar Frecuencias y Deltas, y computar métricas
    for ataque in Ataque:
        exact_csv_path = f"csv/query_exacta_{ataque.name.lower()}.csv"
        csv_exact = pd.read_csv(exact_csv_path)
        frecuenciasExactas, inicio_win, fin_win, j_wins, attack_start_us, attack_end_us = extractExacta(csv_exact, ataque)

        if not frecuenciasExactas:
            print(f"Aviso: No se detectó ataque para {ataque.name}")
            continue

        graficarFrecuencias(ataque, inicio_win, fin_win, attack_start_us, attack_end_us)
        graficarDelta(ataque, inicio_win, fin_win, csv_exact, attack_start_us, attack_end_us)

        metricas = calcularMetricas(ataque, j_wins, attack_start_us, inicio_win, fin_win)
        todas_las_metricas.extend(metricas)

    # 4. Validar en traza limpia
    metricas_clean = validarTrazaLimpia(CLEAN_TRACE_IP)

    # 5. Generar y exportar Tablas Resumen
    df_metricas = pd.DataFrame(todas_las_metricas)
    df_metricas.to_csv("tabla_resumen.csv", index=False)

    md_table = to_markdown_table(df_metricas)
    print("\n" + "=" * 80)
    print("TABLA RESUMEN DE EXPERIMENTOS (ATAQUES)")
    print("=" * 80)
    print(md_table)

    if metricas_clean:
        df_clean = pd.DataFrame(metricas_clean)
        md_clean = to_markdown_table(df_clean)
        print("\n" + "=" * 80)
        print("VALIDACIÓN EN TRAZA LIMPIA SIN ATAQUES")
        print("=" * 80)
        print(md_clean)

    with open("tabla_resumen.md", "w") as f:
        f.write("# Tabla Resumen de Experimentos (Tarea 1 2026)\n\n")
        f.write("## 1. Detección de Ataques (DDoS y Scan)\n\n")
        f.write(md_table + "\n\n")
        if metricas_clean:
            f.write("## 2. Validación en Traza Limpia Sin Ataques\n\n")
            f.write(md_clean + "\n")
    print("\nResumen guardado exitosamente en tabla_resumen.csv y tabla_resumen.md")


if __name__ == "__main__":
    main()
