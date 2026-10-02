#ifndef SLIDING_WINDOW_HPP
#define SLIDING_WINDOW_HPP

#include "count_min.hpp"
#include "count_sketch.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

#pragma pack(push, 1)
struct Record {
  uint64_t ts_us;
  uint32_t src;
  uint32_t dst;
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint8_t proto;
  uint8_t flags;
};
#pragma pack(pop)
static_assert(sizeof(Record) == 24, "El registro de traza debe ocupar 24 bytes");

template <typename SketchType>
class SlidingWindowDetector {
private:
  static const size_t NUM_SUBVENTANAS = 6;
  const uint64_t TAMAÑO_SUBVENTANA = 10000000; // p = 10 segundos en microsegundos
  const uint64_t ANCHO_VENTANA = 60000000;     // W = 60 segundos en microsegundos

  SketchType A;                           // Sketch agregado de la ventana activa
  std::vector<SketchType> ring;           // Anillo de m = 6 sub-sketches
  SketchType last_expired_sketch;         // Guarda la subventana que acaba de expirar para Delta A
  uint64_t ring_N[NUM_SUBVENTANAS] = {0}; // Anillo de contadores escalares de paquetes
  uint64_t total_N = 0;                   // N_j total dentro de la ventana activa

  uint32_t query_key;
  bool is_ddos; // true: analiza dstIP (DDoS); false: analiza srcIP (Scan)
  double phi;

  uint64_t t0 = 0;
  bool initialized = false;
  uint64_t current_q = 1; // Subventana actual (1-indexada)
  uint64_t windows_evaluated = 0;

  std::ostream &out_csv;
  std::istream *exact_csv; // Opcional: puntero a stream de exact_hh para comparar

  static std::string ip_to_string(uint32_t ip) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    return std::string(buf);
  }

  // Estimación del cambio firmado Delta f_j(x) sobre Delta A_j (Sección 6.3)
  int64_t estimar_delta(const SketchType &delta_A, uint32_t key) const {
    if constexpr (std::is_same_v<SketchType, CountMin>) {
      // Para CMS: estimador experimental CMS-mediana (mediana de Delta A_j[r, h_r(x)])
      return delta_A.get_median(key);
    } else {
      // Para CountSketch: estimador estándar de CS (mediana de s_r(x) * Delta A_j[r, h_r(x)])
      return delta_A.get(key);
    }
  }

  void evaluarVentana(uint64_t win_idx, uint64_t tau_us, bool has_delta, const SketchType &delta_A) {
    uint64_t N = 0;
    for (size_t i = 0; i < NUM_SUBVENTANAS; ++i) {
      N += ring_N[i];
    }
    uint64_t threshold = static_cast<uint64_t>(std::ceil(phi * static_cast<double>(N)));
    if (threshold == 0) threshold = 1;

    int64_t raw_estimate = A.get(query_key);
    // Para frecuencia absoluta de paquetes, valores negativos se truncan a 0
    int64_t estimate_f = raw_estimate > 0 ? raw_estimate : 0;
    // Criterio de Heavy Hitter (Sección 3): est_f >= threshold
    int estimate_hh = (estimate_f >= static_cast<int64_t>(threshold)) ? 1 : 0;

    int64_t estimate_delta = 0;
    if (has_delta) {
      estimate_delta = estimar_delta(delta_A, query_key);
    }

    int matches_exact_window = -1;
    int matches_exact_n = -1;
    int exact_hh = -1;
    int matches_exact_hh = -1;
    int64_t exact_f = -1;
    int64_t exact_delta = -1;
    int64_t abs_err = -1;
    double rel_err = -1.0;
    if (exact_csv) {
      std::string line;
      if (!std::getline(*exact_csv, line) || line.empty()) {
        throw std::runtime_error("El CSV exacto terminó antes que la traza de sketches");
      }

      std::stringstream ss(line);
      std::vector<std::string> columns;
      std::string token;
      while (std::getline(ss, token, ',')) columns.push_back(token);
      if (columns.size() < 8 || (columns.size() == 8 && line.back() != ',')) {
        throw std::runtime_error("Fila inválida en el CSV exacto: se esperan 9 columnas");
      }

      uint64_t exact_win = 0;
      uint64_t exact_tau = 0;
      uint64_t exact_N = 0;
      try {
        exact_win = std::stoull(columns[0]);
        exact_tau = std::stoull(columns[1]);
        exact_N = std::stoull(columns[4]);
        exact_f = static_cast<int64_t>(std::stoull(columns[6]));
        exact_hh = std::stoi(columns[7]);
        exact_delta = columns.size() < 9 || columns[8].empty() ? 0 : std::stoll(columns[8]);
      } catch (const std::exception &) {
        throw std::runtime_error("Valor inválido en una fila del CSV exacto");
      }

      matches_exact_window = (exact_win == win_idx && exact_tau == tau_us) ? 1 : 0;
      matches_exact_n = (N == exact_N) ? 1 : 0;
      matches_exact_hh = (estimate_hh == exact_hh) ? 1 : 0;
      uint64_t exact_frequency = static_cast<uint64_t>(exact_f);
      abs_err = (exact_frequency >= static_cast<uint64_t>(estimate_f))
                    ? static_cast<int64_t>(exact_frequency - static_cast<uint64_t>(estimate_f))
                    : static_cast<int64_t>(static_cast<uint64_t>(estimate_f) - exact_frequency);
      rel_err = (exact_frequency > 0)
                    ? (static_cast<double>(abs_err) / static_cast<double>(exact_frequency))
                    : 0.0;
    }

    double t_rel_s = static_cast<double>(tau_us - t0) / 1e6;
    out_csv << win_idx << ',' << tau_us << ',' << t_rel_s << ','
            << ip_to_string(query_key) << ',' << N << ',' << threshold << ','
            << estimate_f << ',' << estimate_hh << ',' << estimate_delta << ','
            << matches_exact_window << ',' << matches_exact_n << ',' << exact_f << ','
            << exact_hh << ',' << matches_exact_hh << ',' << exact_delta << ','
            << abs_err << ',' << rel_err << '\n';

    windows_evaluated++;
  }

public:
  SlidingWindowDetector(const SketchType &prototype, uint32_t key, bool is_ddos,
                        std::ostream &out, std::istream *exact = nullptr, double phi = 0.01)
      : A(prototype), ring(NUM_SUBVENTANAS, prototype),
        last_expired_sketch(prototype), query_key(key), is_ddos(is_ddos),
        phi(phi), out_csv(out), exact_csv(exact) {
    out_csv << "win,tau_us,t_rel_s,key,N,threshold,estimate_f,estimate_hh,"
               "estimate_delta,matches_exact_window,matches_exact_n,exact_f,exact_hh,"
               "matches_exact_hh,exact_delta,abs_err,rel_err\n";

    if (exact_csv) {
      std::string header;
      if (!std::getline(*exact_csv, header) ||
          header != "win,tau_us,t_rel_s,key,N,threshold,exact_f,exact_hh,exact_delta") {
        throw std::runtime_error("CSV exacto vacío o con encabezado inesperado");
      }
    }
  }

  void procesarTraza(std::istream &in) {
    Record pkt;
    // Leer el primer paquete para fijar t0
    if (!in.read(reinterpret_cast<char *>(&pkt), sizeof(Record))) {
      std::cerr << "Error: Traza vacía o ilegible\n";
      return;
    }
    t0 = pkt.ts_us;
    initialized = true;
    current_q = 1;

    // Los paquetes con timestamp exactamente igual a t0 quedan excluidos
    // de la ventana (t0, t0 + W], tal como lo define exact_hh.

    uint64_t last_ts = t0;

    auto procesar_paquete = [&](const Record &r) {
      uint64_t ts = r.ts_us;
      last_ts = ts;
      if (ts <= t0) return; // Solo paquetes estrictamente posteriores a t0

      // Avanzar subventanas según sea necesario
      while (ts > t0 + current_q * TAMAÑO_SUBVENTANA) {
        avanzarSubventana();
      }

      // El paquete cae exactamente en la subventana current_q:
      // (t0 + (current_q - 1)*p, t0 + current_q * p]
      size_t slot = (current_q - 1) % NUM_SUBVENTANAS;
      uint32_t key = is_ddos ? r.dst : r.src;

      // Actualización simultánea del sub-sketch y del agregado A (Requisito 2)
      A.count(key);
      ring[slot].count(key);
      ring_N[slot]++;
    };

    // Procesar el resto de paquetes desde el buffer
    // Usamos un buffer de lectura para acelerar I/O
    const size_t BATCH_SIZE = 4096;
    std::vector<Record> buffer(BATCH_SIZE);
    while (in) {
      in.read(reinterpret_cast<char *>(buffer.data()), BATCH_SIZE * sizeof(Record));
      std::streamsize bytes_read = in.gcount();
      size_t records_read = bytes_read / sizeof(Record);
      for (size_t i = 0; i < records_read; ++i) {
        procesar_paquete(buffer[i]);
      }
    }

    // Al finalizar la traza (EOF), evaluar todas las ventanas completas pendientes hasta last_ts
    while (t0 + current_q * TAMAÑO_SUBVENTANA <= last_ts) {
      avanzarSubventana();
    }
  }

  void avanzarSubventana() {
    // 1. Evaluar si la subventana que termina completa una ventana activa
    if (current_q >= NUM_SUBVENTANAS) {
      uint64_t win_idx = current_q - NUM_SUBVENTANAS;
      uint64_t tau_us = t0 + current_q * TAMAÑO_SUBVENTANA;
      bool has_delta = (win_idx > 0);
      size_t entering_slot = (current_q - 1) % NUM_SUBVENTANAS;

      // Por linealidad (Sección 4 y 6.3):
      // Delta A_j = S_{q_j} - S_{q_j - m} = ring[entering_slot] - last_expired_sketch
      SketchType delta_A = ring[entering_slot] - last_expired_sketch;
      evaluarVentana(win_idx, tau_us, has_delta, delta_A);
    }

    // 2. Avanzar a la siguiente subventana
    current_q++;
    size_t next_slot = (current_q - 1) % NUM_SUBVENTANAS;

    // Si entramos a una subventana posterior a las 6 primeras de precarga,
    // la subventana antigua en next_slot expira:
    if (current_q > NUM_SUBVENTANAS) {
      // Guardar el sub-sketch expirado para el cálculo de Delta A en la siguiente evaluación
      last_expired_sketch = ring[next_slot];
      // Restar explícitamente el sub-sketch expirado del agregado A (Requisito 2)
      A -= ring[next_slot];
      // Limpiar la ranura y el contador escalar
      ring[next_slot].clear();
      ring_N[next_slot] = 0;
    }
  }

  size_t memory_bytes() const {
    // Persistent counters: six ring sketches, aggregate A, and last expired sketch.
    size_t sketch_bytes = (NUM_SUBVENTANAS + 2) * A.memory_bytes();
    size_t scalar_bytes = NUM_SUBVENTANAS * sizeof(uint64_t);
    return sketch_bytes + scalar_bytes;
  }

  uint64_t get_windows_evaluated() const {
    return windows_evaluated;
  }
};

#endif // SLIDING_WINDOW_HPP
