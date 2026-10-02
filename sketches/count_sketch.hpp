#ifndef COUNT_SKETCH_H
#define COUNT_SKETCH_H

#include "../murmurhash/MurmurHash3.h"
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>

class CountSketch {
private:
  int depth;
  int width;
  uint32_t seed_pos;
  uint32_t seed_sgn;
  std::vector<int> table;

  int hash(int row, uint32_t key) const {
    uint32_t result = 0;
    MurmurHash3_x86_32(&key, sizeof(key), seed_pos + static_cast<uint32_t>(row), &result);
    return static_cast<int>(result % static_cast<uint32_t>(width));
  }

  int signHash(int row, uint32_t key) const {
    uint32_t result = 0;
    MurmurHash3_x86_32(&key, sizeof(key), seed_sgn + static_cast<uint32_t>(row), &result);
    return (result & 1) ? -1 : 1;
  }

public:
  CountSketch(int d, int w, uint32_t s_pos, uint32_t s_sgn)
      : depth(d), width(w), seed_pos(s_pos), seed_sgn(s_sgn), table(d * w, 0) {}

  void count(uint32_t key, int c = 1) {
    for (int i = 0; i < depth; i++) {
      table[i * width + hash(i, key)] += signHash(i, key) * c;
    }
  }

  // Estimador de CountSketch: mediana de s_r(x) * C[r, h_r(x)]
  // Válido tanto sobre A_j como sobre el sketch firmado de diferencias Delta A_j
  int64_t get(uint32_t key) const {
    std::vector<int> vals;
    vals.reserve(depth);
    for (int i = 0; i < depth; i++) {
      vals.push_back(table[i * width + hash(i, key)] * signHash(i, key));
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

  CountSketch &operator+=(const CountSketch &rhs) {
    if (depth != rhs.depth || width != rhs.width ||
        seed_pos != rhs.seed_pos || seed_sgn != rhs.seed_sgn) {
      throw std::invalid_argument("Dimensiones o semillas incompatibles en CountSketch::operator+=");
    }
    for (size_t i = 0; i < table.size(); i++) {
      table[i] += rhs.table[i];
    }
    return *this;
  }

  CountSketch &operator-=(const CountSketch &rhs) {
    if (depth != rhs.depth || width != rhs.width ||
        seed_pos != rhs.seed_pos || seed_sgn != rhs.seed_sgn) {
      throw std::invalid_argument("Dimensiones o semillas incompatibles en CountSketch::operator-=");
    }
    for (size_t i = 0; i < table.size(); i++) {
      table[i] -= rhs.table[i];
    }
    return *this;
  }

  friend CountSketch operator-(CountSketch lhs, const CountSketch &rhs) {
    lhs -= rhs;
    return lhs;
  }

  size_t memory_bytes() const {
    return table.size() * sizeof(int);
  }

  int get_depth() const { return depth; }
  int get_width() const { return width; }
  uint32_t get_seed_pos() const { return seed_pos; }
  uint32_t get_seed_sgn() const { return seed_sgn; }
};

#endif // COUNT_SKETCH_H
