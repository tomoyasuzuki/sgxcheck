Demo/%.o: Demo/%.c
	@$(CC) -I/usr/include -I. -c $< -o $@ 
	@echo "CC  <=  $<"

demo: App.o Hash.o
	$(CC) -m64 -I/usr/include -I. -L/usr/bin App.o Hash.o -o demo -lssl -lcrypto
	@echo "LINK =>  demo"
	
democ:
	@rm -f App.o Hash.o demo 90 91 92 93