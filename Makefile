all: scanner puzzlesolver scanner_solver

scanner: scanner.cpp
	g++ --std=c++11 scanner.cpp -o scanner

puzzlesolver: puzzlesolver.cpp
	g++ --std=c++11 puzzlesolver.cpp -o puzzlesolver

scanner_solver: scan_then_solve.cpp
	g++ --std=c++11 scan_then_solve.cpp -o scanner_solver