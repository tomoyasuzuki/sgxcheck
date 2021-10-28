all: 
	make demo

Demo/%.o: Demo/%.c
	@$(CC) -I/usr/include -I. -c $< -o $@ 
	@echo "CC  <=  $<"

demo: App.o Hash.o
	$(CC) -m64 -I/usr/include -I. -L/usr/bin App.o Hash.o -g -o demo -lssl -lcrypto
	@echo "LINK =>  demo"
	
clean:
	@rm -f *.o demo* 0* 1* 2* 3* 4* 5* 6* 7* 8* 9*