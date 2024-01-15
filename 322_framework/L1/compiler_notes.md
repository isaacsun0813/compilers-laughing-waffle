# Compiler Notes

### Compiler 1 Framework
* All our code goes into the /L1/src directory
    * This needs to be a flat directory (ie no subdirectories)
    * The Makefile will combine all cpp and h files that live in this /src directory when you go to make your compiler
* You invoke the L1c script to compile an L1 program (it is the actual "compiler")
    * It invokes whatever program is under src, taking an L1 program file as input and outputting an executable a.out file
* At a finer level:
    * our c++ program will take in the L1 file and generate a prog.S file, which is a txt file containing all of the translated assembly instructions.
    * the L1c script will then take this txt file, execute an assembler and linker (which we don't write) to finally output the a.out executable
* When we compile **our own** c++ program (ie the files that we wrote in src), a new binary is generated in the /bin directory with the name L1
    * the L1c script calls this executable to compile the L1 program that gets passed to it


## Code Structure

### L1 Header

#### Functions
* It seems like Simone's implementation should mostly work for us.

#### Instructions
* 

### Parser
