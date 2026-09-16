#ifndef COUNT_MIN_H
#define COUNT_MIN_H

#include <cstdint>
#include <stdexcept>
class CountMin {
private:
  int depth;
  int width;
  int **sketch;
  long PRIMO = 4294967387;
  int m = 1972;

  // Definimos una familia universal de funciones hash así, funciona siempre que
  // d < PRIMO. Es una implementacion de la primera familia universal mencionada
  // en el articulo de familias universales.
  // La n-esima funcion hash seria \x -> int hash(n,x).
  int hash(long d, long clave) { return ((m * clave + d) % PRIMO) % width; }

public:
  CountMin(int d, int w) : depth{d}, width{w} {
    sketch = new int *[d];
    for (int i = 0; i < d; i++) {
      sketch[i] = new int[w];
      for (int j = 0; j < w; j++)
        sketch[i][j] = 0;
    }
  }

  void count(uint32_t clave) {
    for (int i = 0; i < depth; i++)
      sketch[i][hash(i, clave)]++;
  }

  int get(uint32_t clave) {
    uint32_t k = UINT32_MAX;
    for (int i = 0; i < depth; i++) {
      int estimado = sketch[i][hash(i, clave)];
      k = k < estimado ? k : estimado;
    }
    return k;
  }

  // Implementamos la suma de sketches, como las funciones de hash estan en el
  // codigo, todos los sketches de esta clase son compatibles si sus dimensiones
  // son iguales
  CountMin &operator+=(const CountMin &rhs) {
    if (depth != rhs.depth || width != rhs.width) {
      throw std::invalid_argument("Se intentaron sumar sketches incompatibles, "
                                  "revise las dimensiones de ambos");
    }
    for (int i = 0; i < depth; i++) {
      for (int j = 0; j < width; j++) {
        sketch[i][j] += rhs.sketch[i][j];
      }
    }
    return *this;
  }

  CountMin &operator-=(const CountMin &rhs) {
    if (depth != rhs.depth || width != rhs.width) {
      throw std::invalid_argument(
          "Se intentaron restar sketches incompatibles, "
          "revise las dimensiones de ambos");
    }
    for (int i = 0; i < depth; i++) {
      for (int j = 0; j < width; j++) {
        sketch[i][j] -= rhs.sketch[i][j];
      }
    }
    return *this;
  }

  // Esto es innecesario pero implentarlo es gratis
  CountMin &operator*=(const int rhs) {
    for (int i = 0; i < depth; i++) {
      for (int j = 0; j < width; j++) {
        sketch[i][j] += rhs;
      }
    }
    return *this;
  }
};

#endif
