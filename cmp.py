import argparse
import csv
import sys
from itertools import zip_longest


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compara las frecuencias (columna 5) entre dos archivos CSV."
    )
    parser.add_argument("archivo1", help="Ruta al primer archivo CSV")
    parser.add_argument("archivo2", help="Ruta al segundo archivo CSV")
    parser.add_argument(
        "--no-header",
        action="store_true",
        help="Indica que los archivos NO tienen fila de encabezado (por defecto se asume que sí tienen)",
    )
    parser.add_argument(
        "-d", "--delimiter", default=",", help="Delimitador del CSV (por defecto: ',')"
    )
    parser.add_argument(
        "-n",
        "--numeric",
        action="store_true",
        help="Interpreta las frecuencias como números float para evitar falsos positivos por formato (ej. 100 vs 100.0)",
    )
    return parser.parse_args()


def extraer_frecuencias(
    ruta_archivo, tiene_encabezado=True, delimitador=",", es_numerico=False
):
    frecuencias = []
    try:
        with open(ruta_archivo, mode="r", encoding="utf-8") as f:
            lector = csv.reader(f, delimiter=delimitador)
            if tiene_encabezado:
                next(lector, None)

            for num_fila, fila in enumerate(lector, start=2 if tiene_encabezado else 1):
                if len(fila) >= 5:
                    valor_raw = fila[4].strip()
                    if es_numerico:
                        try:
                            # Reemplaza coma por punto por si hay formatos decimales europeos/latinoamericanos
                            frecuencias.append(float(valor_raw.replace(",", ".")))
                        except ValueError:
                            print(
                                f"Error: Fila {num_fila} en '{ruta_archivo}' tiene un valor no numérico: '{valor_raw}'",
                                file=sys.stderr,
                            )
                            sys.exit(1)
                    else:
                        frecuencias.append(valor_raw)
                else:
                    print(
                        f"Advertencia: Fila {num_fila} en '{ruta_archivo}' tiene menos de 5 campos.",
                        file=sys.stderr,
                    )
    except FileNotFoundError:
        print(f"Error: No se encontró el archivo '{ruta_archivo}'", file=sys.stderr)
        sys.exit(1)

    return frecuencias


def main():
    args = parse_args()
    tiene_encabezado = not args.no_header

    freq1 = extraer_frecuencias(
        args.archivo1, tiene_encabezado, args.delimiter, args.numeric
    )
    freq2 = extraer_frecuencias(
        args.archivo2, tiene_encabezado, args.delimiter, args.numeric
    )

    print(
        f"Registros leídos: {len(freq1)} en '{args.archivo1}' | {len(freq2)} en '{args.archivo2}'\n"
    )

    # 1. Comparación fila por fila
    if freq1 == freq2:
        print(
            "✓ Coincidencia exacta: Ambos archivos tienen idéntica secuencia fila por fila."
        )
    else:
        print("✗ Discrepancia fila por fila:")
        diferencias = 0
        for i, (v1, v2) in enumerate(zip_longest(freq1, freq2), start=1):
            if v1 != v2:
                print(f"  - Fila {i}: {v1} != {v2}")
                diferencias += 1
                if diferencias >= 5:
                    print("  - ... (se omiten más diferencias)")
                    break

    print("-" * 50)

    # 2. Comparación de conjuntos únicos
    set1, set2 = set(freq1), set(freq2)
    if set1 == set2:
        print(
            "✓ Coincidencia de catálogo: Ambos archivos contienen el mismo set de frecuencias únicas."
        )
    else:
        solo_en_1 = set1 - set2
        solo_en_2 = set2 - set1
        if solo_en_1:
            print(
                f"Frecuencias solo en {args.archivo1} ({len(solo_en_1)}): {list(solo_en_1)[:5]}"
            )
        if solo_en_2:
            print(
                f"Frecuencias solo en {args.archivo2} ({len(solo_en_2)}): {list(solo_en_2)[:5]}"
            )


if __name__ == "__main__":
    main()
