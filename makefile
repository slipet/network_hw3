all: test save

test: test.c
	gcc -g -Wall -o test test.c -lpcap
save: save_to_file.c	
	gcc -g -Wall -o save save_to_file.c -lpcap
clean:
	rm -rf *.o test save