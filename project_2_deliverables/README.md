## Authors(Group 16)
Arnór Daníel Moncada - arnorm20@ru.is
Sindri Másson - sindrim19@ru.is
## Problems completed
We completed problems 1, 2 and 3, however not the bonus. We believe we should get full marks for these parts.
## COMPILING
The scanner is in scanner.cpp and the puzzlesolver in puzzlesolver.cpp, the puzzlesolver has its own scanner. Both can be compiled using make on MacOS/Linux
The commands we use are the following:
scanner:
    g++ --std=c++11 scanner.cpp -o scanner
puzzlesolver:
	g++ --std=c++11 puzzlesolver.cpp -o puzzlesolver
## USAGE
scanner:
    To run the scanner ./scanner <severIp> <lowPort> <highPort> in terminal.
puzzlesolver:
    To run the puzzlesolver ./scanner_solver <severIp> in terminal.
## FUNCTIONALITY
The scanner will take the low/high ports, scan all the ports in the range and print them to terminal.

The puzzlesolver takes the ip and scans the ports from 4000-4100 then start solving the puzzle. All the parts of the puzzlesolving should be robust and the puzzle should always be solved and stop when the knocks have been conducted. If the last phrase is "You have knocked. You may enter" the program will even tell you it succeeded.
## Time to complete
The group spent a combined 60+ hours on this project.