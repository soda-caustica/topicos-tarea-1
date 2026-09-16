#include "count_min.hpp"
#include <iostream>

int main(){
  int d = 3;
  int w = 3;
  int arr[]  = {1,2,1,1,3,2,1,1,2,3,4,2};
  int arr2[] = {3,1,2,1,2,1,1,1,2,3,4,1};

  CountMin sketch1 = CountMin(d,w);
  CountMin sketch2 = CountMin(d,w);
  CountMin sketchCombinado = CountMin(d,w);

  for(int i = 0; i < 12; i++){
    sketch1.count(arr[i]);
    sketch2.count(arr2[i]);
    sketchCombinado.count(arr[i]);
    sketchCombinado.count(arr2[i]);
  }
  sketch1 += sketch2;
  for(int i = 1; i <= 4; i++){
    std::cout << sketch1.get(i) - sketchCombinado.get(i) << '\n';
  }
}
