## Authors(Group 16)
Arnór Daníel Moncada - arnorm20@ru.is
Sindri Másson - sindrim19@ru.is
## Problems completed
We completed problems 1, 2 and 3, however not the bonus. We believe we should get full marks for these parts.
## COMPILING
The scanner and puzzlesolver are in the same file so just run make on MacOS/Linux
The command I use is the following:
scanner_solver:
	g++ --std=c++11 scan_then_solve.cpp -o scanner_solver
## USAGE
scanner_solver:
    To run the program ./scanner_solver <severIp> <lowPort> <highPort> in terminal.
## FUNCTIONALITY
The program will take the low/high ports, scan all the ports in the range and them start solving the puzzle. All the parts of the puzzlesolving should be robust and the puzzle should always be solved and stop when the knocks have been conducted. If the last phrase is "You have knocked. You may enter" the program will even tell you it succeeded.
## Time to complete
The group spent a combined 60+ hours on this project.