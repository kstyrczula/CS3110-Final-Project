test:
	ocamlbuild -use-ocamlfind test.byte && ./test.byte -runner sequential

clean:
	ocamlbuild -clean
