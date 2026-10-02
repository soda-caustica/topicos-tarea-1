## Tarea 1 de Topicos de Manejo de Grandes Volumenes de datos

# Ejecución de experimentos

Desde la raíz del proyecto, compila los ejecutables y el conversor:

```bash
make
make -C codigo_entregado pcap2bin
```

Genera las trazas de ataque desde una traza PCAP o BIN. El inicio predeterminado es 300 s y la duración 30 s; ajusta esos valores si la traza es más corta. La semilla usada en el informe es 42.

```bash
python3 generar_trazas.py trazas/traza.pcap --seed <semilla> --pcap2bin codigo_entregado/pcap2bin
```

El comando genera `trazas/traza.bin`, `trazas/traza_ddos.bin`, `trazas/traza_scan.bin`, `gt_ddos.json`, `gt_scan.json` e `ips_ataques.json`, ademas imprime las ips por consola.

Ejecuta los experimentos usando las IPs extraídas:

```bash
python experimentos.py <ip_scan> <ip_ddos>
```

Los d y w estan fijos en el script de experimentos, por lo que para generar graficos y tablas no se puede elegir, pero si se quiere obtener un csv con resultados, los scripts min_hh y sketch_hh funcionan asi:

```bash 
./min_hh <traza.bin> <ip> <d> <w> <0=scan, 1=ddos> [<exact_query.csv>] <output.csv> [seed]
```
Se puede proveer un csv con los valores exactos, equivalente a usar exact_hh, eso incluirá comparaciones en el csv resultante

Los resultados se guardan en `csv/`, los gráficos en la raíz y el resumen en `tabla_resumen.csv` y `tabla_resumen.md`.
