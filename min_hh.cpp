#include "count_min.hpp"
#include <arpa/inet.h>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <ios>
#include <iostream>
#include <netinet/in.h>
#include <string>

class Detector_Min {
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
  CountMin *sketch_principal;
  CountMin *subsketches[NUM_SUBVENTANAS];
  int contadores[NUM_SUBVENTANAS] = {0};
  uint64_t t0 = 0;
  uint64_t inicioRanura = 0;
  uint32_t ip;
  char ranuraActual = 0;
  std::ifstream &input;
  std::ofstream &output;
  Paquete paqueteActual = {};
  bool ddos;
  uint64_t prevEstimate = 0;

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
    if (contadores[ranuraActual] == 0)
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

    uint64_t estimate = sketch_principal->get(ip);
    int64_t delta = estimate - prevEstimate;

    output << ((inicioRanura - t0) / TAMAÑO_SUBVENTANA) - NUM_SUBVENTANAS << ','
           << inicioRanura << ',' << ((double)(inicioRanura - t0) / 1e6) << ','
           << intToIP(ip) << ',' << N << ',' << threshold << ',' << estimate
           << ',' << (estimate >= threshold ? 1 : 0) << ',' << delta << '\n';

    prevEstimate = estimate;
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
  Detector_Min(int d, int w, std::ifstream &infile, std::ofstream &outfile,
               bool ddos, uint32_t ip)
      : input(infile), output(outfile), ddos(ddos), ip(ip) {
    sketch_principal = new CountMin(d, w);
    for (int i = 0; i < 6; i++) {
      subsketches[i] = new CountMin(d, w);
    }
    if (!obtenerPaquete()) {
      std::cout << "No se pudo leer el primer paquete";
      exit(EXIT_FAILURE);
    }
    inicioRanura = paqueteActual.ts_us;
    t0 = inicioRanura;
    output << "win,tau_us,t_rel_s,key,N,threshold,estimate_f,estimate_hh,"
              "estimate_delta\n";
  }

  bool procesar() {
    while (paqueteActual.ts_us > inicioRanura + TAMAÑO_SUBVENTANA) {
      ranuraActual = (ranuraActual + 1) % NUM_SUBVENTANAS;
      inicioRanura += TAMAÑO_SUBVENTANA;
      cambiarVentana();
    }
    uint32_t ip_addr = ddos ? paqueteActual.dst : paqueteActual.src;
    sketch_principal->count(ip_addr);
    subsketches[ranuraActual]->count(ip_addr);
    contadores[ranuraActual]++;

    if (!obtenerPaquete()) {
      return false;
    }
    return true;
  }

  int revisarHH(uint32_t ip, float phi) {
    int sum = 0;
    for (int i = 0; i < NUM_SUBVENTANAS; i++) {
      sum += contadores[i];
    }
    sum *= phi;
    return sketch_principal->get(ip) > sum;
  }
};

uint32_t ip_to_u32(const char *ip) {
  struct in_addr addr;
  if (inet_pton(AF_INET, ip, &addr) != 1) {
    throw std::invalid_argument("Invalid IPv4 address");
  }
  return ntohl(addr.s_addr); // convert network byte order to host order
}

int main(int argc, char **argv) {
  if (argc != 7) {
    std::cout << "Uso: " << argv[0]
              << " <traza> <ip> <d> <w> <0 para scan, 1 para ddos> <archivo "
                 "csv para resultados>\n";
    exit(EXIT_FAILURE);
  }
  std::ifstream traza;
  std::ofstream csv;

  uint32_t ip = ip_to_u32(argv[2]);
  bool scan = atoi(argv[5]);
  traza.open(argv[1], std::ios::binary | std::ios::in);
  csv.open(argv[6]);
  Detector_Min det =
      Detector_Min(atoi(argv[3]), atoi(argv[4]), traza, csv, scan, ip);
  while (det.procesar()) {
  }
}
