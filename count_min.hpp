#ifndef COUNT_MIN_H
#define COUNT_MIN_H

#include <cstdint>
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
    for (int i = 0; i < d; i++){
      sketch[i] = new int[w];
      for (int j = 0; j < w; j++)
        sketch[i][j] = 0;
    }
  }

  void count(uint32_t clave){
    for(int i = 0; i < depth; i++)
      sketch[i][hash(i,clave)]++;
  }

  int get(uint32_t clave){
    uint32_t k = UINT32_MAX;
    for (int i = 0; i < depth; i++){
      int estimado = sketch[i][hash(i,clave)];
      k = k < estimado ? k : estimado;
    }
    return k;
  }
};

#endif
