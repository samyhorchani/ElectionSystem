all : tests main simulation directories zip

zip :
	zip Projet_Horchani_Dormant CompteRendu_Horchani_Dormant.pdf commande.txt simulation.c main.c tests.c bpd.c bpd.h bdc.c bdc.h dec_sec.c dec_sec.h dev_out_crypto.c dev_out_crypto.h Makefile

directories :
	mkdir -p Blockchain RandomDatas Tests ./Tests/Analyse ./Tests/Blockchain 

simulation : simulation.o main.o dev_out_crypto.o dec_sec.o bdc.o bpd.o
	gcc -o simulation simulation.o dev_out_crypto.o dec_sec.o bdc.o bpd.o -lssl -lcrypto

main : main.o dev_out_crypto.o dec_sec.o bdc.o bpd.o
	gcc -o main main.o dev_out_crypto.o dec_sec.o bdc.o bpd.o -lssl -lcrypto

tests : tests.o dev_out_crypto.o dec_sec.o bdc.o bpd.o
	gcc -o tests tests.o dev_out_crypto.o dec_sec.o bdc.o bpd.o -lssl -lcrypto

simulation.o : simulation.c dev_out_crypto.h dec_sec.h bdc.h bpd.h
	gcc -c simulation.c -lssl -lcrypto

main.o : main.c dev_out_crypto.h dec_sec.h bdc.h bpd.h
	gcc -c main.c -lssl -lcrypto

tests.o : tests.c dev_out_crypto.h dec_sec.h bdc.h bpd.h
	gcc -c tests.c -lssl -lcrypto

bpd.o : bpd.c bpd.h bdc.h dec_sec.h
	gcc -c bpd.c -lssl -lcrypto

bdc.o : bdc.c bdc.h dec_sec.h
	gcc -c bdc.c

dec_sec.o : dec_sec.c dec_sec.h dev_out_crypto.h
	gcc -c dec_sec.c

dev_out_crypto.o : dev_out_crypto.c dev_out_crypto.h
	gcc -c dev_out_crypto.c

clean :
	rm -f *.o tests main simulation directories
	rm -r Blockchain RandomDatas Tests Projet_Horchani_Dormant.zip