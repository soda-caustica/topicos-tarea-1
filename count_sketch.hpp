
#ifndef COUNT_SKETCH_H
#define COUNT_SKETCH_H

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>
class CountSketch {
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
  int hash(long d, long clave) { return (m * clave + d) % PRIMO; }
  int signHash(long d, long clave) { return hash(d, clave) % 2 == 1 ? -1 : 1; }

public:
  CountSketch(int d, int w) : depth{d}, width{w} {
    sketch = new int *[d];
    for (int i = 0; i < d; i++) {
      sketch[i] = new int[w];
      for (int j = 0; j < w; j++)
        sketch[i][j] = 0;
    }
  }

  /// Esto no es muy eficiente, si tengo problemas de rendimiento deberia hacer
  /// que la funcion hash corra solo una vez
  void count(uint32_t clave) {
    for (int i = 0; i < depth; i++) {
      sketch[i][hash(i, clave) % width] += signHash(i, clave);
    }
  }

  float get(uint32_t clave) {
    std::vector<int> arr;
    arr.reserve(depth);
    for (int i = 0; i < depth; i++) {
      arr.push_back(sketch[i][hash(i, clave) % width]*signHash(i,clave));
    }
    int mid = arr.size()/2;

    //sacamos mediana
    if (arr.size() % 2 == 1){
      std::nth_element(arr.begin(),arr.begin()+mid,arr.end());
      return arr[mid];
    } else{
      std::sort(arr.begin(),arr.end());
      return (arr[mid-1]+arr[mid])/2.0;
    }
  }

  // Implementamos la suma de sketches, como las funciones de hash estan en el
  // codigo, todos los sketches de esta clase son compatibles si sus dimensiones
  // son iguales
  CountSketch &operator+=(const CountSketch &rhs) {
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

  CountSketch &operator-=(const CountSketch &rhs) {
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
  CountSketch &operator*=(const int rhs) {
    for (int i = 0; i < depth; i++) {
      for (int j = 0; j < width; j++) {
        sketch[i][j] *= rhs;
      }
    }
    return *this;
  }
};

#endif
