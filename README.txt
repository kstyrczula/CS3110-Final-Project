Instructions to compile and run our project:

1. Install lablgtk2
  On the course VM, it should work if you do "sudo apt-get install gtk2.0"
followed by "opam install lablgtk".

2. Open utop and enter these commands:

Topdirs.dir_directory (Sys.getenv "OCAML_TOPLEVEL_PATH");;
#use "topfind";;
#require "lablgtk2";;
#require "str";;
#mod_use "state.ml";;
#mod_use "cipher.ml";;;
#mod_use "decipher.ml";;
#use "gui.ml";;

This will produce some warnings, but they can be safely ignored. It may still
work if you omit the first two comands, but we've included them to be safe.

3. Typing "make" or "make test" in Terminal should run our test suite.
  The test suite will take a bit to generate random tests before running the
test suite. Generating the tests takes about 30 seconds on Alex's VM. The VM
itself reports about 20 seconds.