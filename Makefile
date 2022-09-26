all: scanner puzzlesolver

scanner: scanner.cpp
	g++ --std=c++11 scanner.cpp -o scanner

puzzlesolver: puzzlesolver.cpp
	g++ --std=c++11 puzzlesolver.cpp -o puzzlesolver