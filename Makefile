CXX ?= g++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra

MURMURHASH_SRC := murmurhash/MurmurHash3.cpp
MURMURHASH_HEADER := murmurhash/MurmurHash3.h

.PHONY: all clean

all: min_hh sketch_hh

min_hh: min_hh.cpp sketches/count_min.hpp $(MURMURHASH_HEADER) $(MURMURHASH_SRC)
	$(CXX) $(CXXFLAGS) -o $@ min_hh.cpp $(MURMURHASH_SRC)

sketch_hh: sketch_hh.cpp sketches/count_sketch.hpp $(MURMURHASH_HEADER) $(MURMURHASH_SRC)
	$(CXX) $(CXXFLAGS) -o $@ sketch_hh.cpp $(MURMURHASH_SRC)

clean:
	rm -f min_hh sketch_hh