all: scanner

client: scanner.cpp
	g++ --std=c++11 scanner.cpp -o scanner
