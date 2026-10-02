CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wno-implicit-fallthrough

MURMURHASH_SRC := murmurhash/MurmurHash3.cpp
MURMURHASH_HEADER := murmurhash/MurmurHash3.h
SLIDING_WINDOW_HEADER := sketches/sliding_window.hpp

.PHONY: all clean

all: exact_hh min_hh sketch_hh

exact_hh: codigo_entregado/exact_hh.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

min_hh: min_hh.cpp sketches/count_min.hpp $(SLIDING_WINDOW_HEADER) $(MURMURHASH_HEADER) $(MURMURHASH_SRC)
	$(CXX) $(CXXFLAGS) -o $@ min_hh.cpp $(MURMURHASH_SRC)

sketch_hh: sketch_hh.cpp sketches/count_sketch.hpp $(SLIDING_WINDOW_HEADER) $(MURMURHASH_HEADER) $(MURMURHASH_SRC)
	$(CXX) $(CXXFLAGS) -o $@ sketch_hh.cpp $(MURMURHASH_SRC)

clean:
	rm -f exact_hh min_hh sketch_hh