#include "count_min.hpp"
#include <iostream>

int main(){
  int d = 3;
  int w = 3;
  int arr[] = {1,2,1,1,3,2,1,1,2,3,4,2};
  CountMin sketch = CountMin(d,w);
  for(int i = 0; i < 12; i++)
    sketch.count(arr[i]);
  for(int i = 1; i <= 4; i++){
    std::cout << sketch.get(i) << '\n';
  }
}
