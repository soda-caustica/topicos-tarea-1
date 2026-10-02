#ifndef COUNT_MIN_H
#define COUNT_MIN_H

#include "../murmurhash/MurmurHash3.h"
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>

class CountMin {
private:
  int depth;
  int width;
  uint32_t seed;
  std::vector<int> table;

  int hash(int row, uint32_t key) const {
    uint32_t result = 0;
    MurmurHash3_x86_32(&key, sizeof(key), seed + static_cast<uint32_t>(row), &result);
    return static_cast<int>(result % static_cast<uint32_t>(width));
  }

public:
  CountMin(int d, int w, uint32_t seed)
      : depth(d), width(w), seed(seed), table(d * w, 0) {}

  void count(uint32_t key, int c = 1) {
    for (int i = 0; i < depth; i++) {
      table[i * width + hash(i, key)] += c;
    }
  }

  // Estimador estándar de Count-Min Sketch: mínimo de las filas
  int64_t get(uint32_t key) const {
    int64_t min_val = INT64_MAX;
    for (int i = 0; i < depth; i++) {
      int val = table[i * width + hash(i, key)];
      if (val < min_val) {
        min_val = val;
      }
    }
    return min_val;
  }

  // Estimador experimental CMS-mediana (Sección 6.3 del enunciado)
  // Utilizado sobre Delta A_j: mediana_{r=1}^d [Delta A_j[r, h_r(x)]]
  int64_t get_median(uint32_t key) const {
    std::vector<int> vals;
    vals.reserve(depth);
    for (int i = 0; i < depth; i++) {
      vals.push_back(table[i * width + hash(i, key)]);
    }
    size_t mid = vals.size() / 2;
    if (vals.size() % 2 == 1) {
      std::nth_element(vals.begin(), vals.begin() + mid, vals.end());
      return vals[mid];
    } else {
      std::sort(vals.begin(), vals.end());
      return (static_cast<int64_t>(vals[mid - 1]) + vals[mid]) / 2;
    }
  }

  void clear() {
    std::fill(table.begin(), table.end(), 0);
  }

  CountMin &operator+=(const CountMin &rhs) {
    if (depth != rhs.depth || width != rhs.width || seed != rhs.seed) {
      throw std::invalid_argument("Dimensiones o semillas incompatibles en CountMin::operator+=");
    }
    for (size_t i = 0; i < table.size(); i++) {
      table[i] += rhs.table[i];
    }
    return *this;
  }

  CountMin &operator-=(const CountMin &rhs) {
    if (depth != rhs.depth || width != rhs.width || seed != rhs.seed) {
      throw std::invalid_argument("Dimensiones o semillas incompatibles en CountMin::operator-=");
    }
    for (size_t i = 0; i < table.size(); i++) {
      table[i] -= rhs.table[i];
    }
    return *this;
  }

  friend CountMin operator-(CountMin lhs, const CountMin &rhs) {
    lhs -= rhs;
    return lhs;
  }

  size_t memory_bytes() const {
    return table.size() * sizeof(int);
  }

  int get_depth() const { return depth; }
  int get_width() const { return width; }
  uint32_t get_seed() const { return seed; }
};

#endif // COUNT_MIN_H
