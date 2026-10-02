#include "sketches/count_min.hpp"
#include "sketches/sliding_window.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

static uint32_t ip_to_u32(const char *ip_str) {
  struct in_addr addr;
  if (inet_pton(AF_INET, ip_str, &addr) != 1) {
    throw std::invalid_argument("Direccion IPv4 invalida: " + std::string(ip_str));
  }
  return ntohl(addr.s_addr);
}

int main(int argc, char **argv) {
  if (argc < 7) {
    std::cerr << "Uso: " << argv[0]
              << " <traza.bin> <ip> <d> <w> <0=scan, 1=ddos> [<exact_query.csv>] <output.csv> [seed]\n"
              << "Ejemplo con CSV exacto:\n"
              << "  " << argv[0] << " traza_ddos.bin 222.160.209.129 5 1024 1 exact.csv out.csv 42\n"
              << "Ejemplo autonomo:\n"
              << "  " << argv[0] << " traza_ddos.bin 222.160.209.129 5 1024 1 out.csv 42\n";
    return EXIT_FAILURE;
  }

  std::string traza_path = argv[1];
  uint32_t ip = ip_to_u32(argv[2]);
  int d = std::stoi(argv[3]);
  int w = std::stoi(argv[4]);
  bool is_ddos = (std::stoi(argv[5]) != 0);

  std::string exact_path = "";
  std::string out_path = "";
  uint32_t seed = 42;

  if (argc == 7) {
    out_path = argv[6];
  } else if (argc == 8) {
    // Si argv[6] es "none" o "-", no hay CSV exacto y argv[7] es salida
    std::string arg6 = argv[6];
    if (arg6 == "none" || arg6 == "-") {
      out_path = argv[7];
    } else {
      exact_path = arg6;
      out_path = argv[7];
    }
  } else { // argc >= 9
    std::string arg6 = argv[6];
    if (arg6 != "none" && arg6 != "-") {
      exact_path = arg6;
    }
    out_path = argv[7];
    seed = static_cast<uint32_t>(std::stoul(argv[8]));
  }

  std::ifstream traza_file(traza_path, std::ios::binary);
  if (!traza_file) {
    std::cerr << "Error: No se pudo abrir la traza binaria: " << traza_path << "\n";
    return EXIT_FAILURE;
  }

  std::ofstream out_file(out_path);
  if (!out_file) {
    std::cerr << "Error: No se pudo abrir el archivo de salida: " << out_path << "\n";
    return EXIT_FAILURE;
  }

  std::unique_ptr<std::ifstream> exact_file;
  if (!exact_path.empty()) {
    exact_file = std::make_unique<std::ifstream>(exact_path);
    if (!*exact_file) {
      std::cerr << "Aviso: No se pudo abrir el archivo exacto: " << exact_path << ". Continuando sin ground truth.\n";
      exact_file.reset();
    }
  }

  CountMin prototype(d, w, seed);
  SlidingWindowDetector<CountMin> detector(
      prototype, ip, is_ddos, out_file, exact_file ? exact_file.get() : nullptr);

  size_t mem_bytes = detector.memory_bytes();
  std::cerr << "[Count-Min Sketch] d=" << d << ", w=" << w << ", seed=" << seed
            << " | Memoria contadores (8 sketches persistentes + contadores): "
            << mem_bytes << " B (" << (static_cast<double>(mem_bytes) / 1024.0) << " KB)\n";

  detector.procesarTraza(traza_file);

  std::cerr << "Ventanas evaluadas: " << detector.get_windows_evaluated() << "\n";
  return EXIT_SUCCESS;
}
