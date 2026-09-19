#include "sketches/count_sketch.hpp"
#include <arpa/inet.h>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <ios>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <string>

class Detector_Sketch {
private:
  struct Paquete {
    uint64_t ts_us;
    uint32_t src;
    uint32_t dst;
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint8_t proto;
    uint8_t flags;
  };
  static const int NUM_SUBVENTANAS = 6;
  static const int TAMAÑO_SUBVENTANA = 10000000; // 10 segundos
  CountSketch *sketch_principal;
  CountSketch *subsketches[NUM_SUBVENTANAS];
  int contadores[NUM_SUBVENTANAS] = {0};
  uint64_t t0 = 0;
  uint64_t inicioRanura = 0;
  uint32_t ip;
  char ranuraActual = 0;
  std::ifstream &input;
  std::ofstream &output;
  std::ifstream &exacto; // stream con resultados exactos (csv)
  Paquete paqueteActual = {};
  bool ddos;
  int64_t prevEstimate = 0;

  int obtenerPaquete() {
    if (input.read((char *)&(paqueteActual.ts_us), 8) &&
        input.read((char *)&(paqueteActual.src), 4) &&
        input.read((char *)&(paqueteActual.dst), 4) &&
        input.read((char *)&(paqueteActual.sport), 2) &&
        input.read((char *)&(paqueteActual.dport), 2) &&
        input.read((char *)&(paqueteActual.len), 2) &&
        input.read((char *)&(paqueteActual.proto), 1) &&
        input.read((char *)&(paqueteActual.flags), 1))
      return 1;
    return 0;
  }

  void cambiarVentana() {
    if (contadores[NUM_SUBVENTANAS - 1] ==
        0) // Revisamos si las 6 subventanas fueron rellenadas antes de escribir
           // los resultados
      return;
    escribirResultados();
    *sketch_principal -= *subsketches[ranuraActual];
    *subsketches[ranuraActual] *= 0;
    contadores[ranuraActual] = 0;
  };

  void escribirResultados() {
    uint64_t N = 0;
    for (int i = 0; i < NUM_SUBVENTANAS; ++i) {
      N += contadores[i];
    }
    uint64_t threshold = std::ceil(0.01 * double(N));

    int64_t raw_estimate = sketch_principal->get(ip);
    int64_t delta = raw_estimate - prevEstimate;

    // Leer siguiente línea del csv exacto y obtener la columna N (índice 4)
    uint64_t N_exact = 0;
    uint64_t f_exact = 0;
    if (exacto.good()) {
      std::string line;
      if (std::getline(exacto, line)) {
        if (!line.empty()) {
          std::stringstream ss(line);
          std::string tok;
          int col = 0;
          while (std::getline(ss, tok, ',')) {
            if (col == 4) {
              try {
                N_exact = std::stoull(tok);
              } catch (...) {
                N_exact = 0;
              }
            }
            if (col == 6) {
              try {
                f_exact = std::stoull(tok);
              } catch (...) {
                f_exact = 0;
              }
              break;
            }
            col++;
          }
        }
      }
    }

    output << ((inicioRanura - t0) / TAMAÑO_SUBVENTANA) - NUM_SUBVENTANAS << ','
           << inicioRanura << ',' << ((double)(inicioRanura - t0) / 1e6) << ','
           << intToIP(ip) << ',' << N << ',' << threshold << ',' << raw_estimate
           << ',' << revisarHH(ip, 0.01) << ',' << delta << ','
           << (N == N_exact ? 1 : 0) << ','
           << (f_exact > raw_estimate ? f_exact - raw_estimate
                                      : raw_estimate - f_exact)
           << ','
           << (raw_estimate == 0
                   ? 0.0
                   : (f_exact > raw_estimate ? f_exact - raw_estimate
                                             : raw_estimate - f_exact) /
                         (double)raw_estimate)
           << '\n';

    prevEstimate = raw_estimate;
  }

  // Se lo pedi a la IA
  std::string intToIP(uint32_t address) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (address >> 24) & 0xFFu,
                  (address >> 16) & 0xFFu, (address >> 8) & 0xFFu,
                  address & 0xFFu);
    return std::string(buf);
  }

public:
  Detector_Sketch(int d, int w, std::ifstream &infile, std::ofstream &outfile,
                  bool ddos, uint32_t ip, std::ifstream &exacto_csv)
      : input(infile), output(outfile), ddos(ddos), ip(ip), exacto(exacto_csv) {
    uint16_t gen = rand() % INT16_MAX;
    uint16_t gen2 = rand() % INT16_MAX; // Aseguramos que m y m2 sean distintos
    sketch_principal =
        new CountSketch(d, w, gen, gen2);
    for (int i = 0; i < 6; i++) {
      subsketches[i] =
          new CountSketch(d, w, gen, gen2);
    }
    if (!obtenerPaquete()) {
      std::cout << "No se pudo leer el primer paquete";
      exit(EXIT_FAILURE);
    }
    inicioRanura = paqueteActual.ts_us;
    // Alinear comportamiento con exact_hh: exact_hh usa ventanas (t0, t0+W]
    // por eso dejamos t0 = inicioRanura - 1 para que la primera ventana
    // no incluya el paquete con timestamp == inicioRanura.
    if (inicioRanura > 0)
      t0 = inicioRanura - 1;
    else
      t0 = 0;
    // descartar encabezado del csv exacto
    std::string header;
    if (exacto.good())
      std::getline(exacto, header);

    output << "win,tau_us,t_rel_s,key,N,threshold,estimate_f,estimate_hh,"
              "estimate_delta,matches_exact_n,abs_err,rel_err\n";
  }

  bool procesar() {
    if (!obtenerPaquete()) {
      return false;
    }
    while (paqueteActual.ts_us > inicioRanura + TAMAÑO_SUBVENTANA) {
      ranuraActual = (ranuraActual + 1) % NUM_SUBVENTANAS;
      inicioRanura += TAMAÑO_SUBVENTANA;
      cambiarVentana();
    }
    uint32_t ip_addr = ddos ? paqueteActual.dst : paqueteActual.src;
    sketch_principal->count(ip_addr);
    subsketches[ranuraActual]->count(ip_addr);
    contadores[ranuraActual]++;
    return true;
  }

  int revisarHH(uint32_t ip, float phi) {
    int sum = 0;
    for (int i = 0; i < NUM_SUBVENTANAS; i++) {
      sum += contadores[i];
    }
    sum = ceil(phi * (double)sum);
    return sketch_principal->get(ip) > sum;
  }
};

// se lo pedi a la IA
uint32_t ip_to_u32(const char *ip) {
  struct in_addr addr;
  if (inet_pton(AF_INET, ip, &addr) != 1) {
    throw std::invalid_argument("Invalid IPv4 address");
  }
  return ntohl(addr.s_addr); // convert network byte order to host order
}

int main(int argc, char **argv) {
  srand(time(NULL));
  if (argc != 8) {
    std::cout << "Uso: " << argv[0]
              << " <traza> <ip> <d> <w> <0 para scan, 1 para ddos> <archivo "
                 "con resultados exactos> <archivo "
                 "csv para resultados>\n";
    exit(EXIT_FAILURE);
  }
  std::ifstream traza;
  std::ofstream csv;
  std::ifstream exacto;

  uint32_t ip = ip_to_u32(argv[2]);
  bool scan = atoi(argv[5]);
  traza.open(argv[1], std::ios::binary | std::ios::in);
  exacto.open(argv[6]);
  csv.open(argv[7]);

  Detector_Sketch det = Detector_Sketch(atoi(argv[3]), atoi(argv[4]), traza,
                                        csv, scan, ip, exacto);

  while (det.procesar()) {
  }
  traza.close();
  csv.close();
  exacto.close();
}
