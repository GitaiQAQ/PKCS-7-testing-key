NAME		:= tm
obj-m		:= $(NAME).o
# $(shell uname -r)
KDIR 		:= /lib/modules/4.15.0-30deepin-generic/build

$(NAME)-y	:= main.o cert.o

all: signing_key.x509 sign-file modules

modules:
	make -C $(KDIR) M=$(PWD) modules

clean-files := sign-file extract-cert test.txt.p7s signing_key.pem signing_key.x509

clean:
	make -C $(KDIR) M=$(PWD) clean

signing_key.pem: 
	openssl req -new -nodes -utf8 -sha256 -days 36500 -batch -x509 -config x509.genkey -outform PEM -out $@ -keyout $@

sign-file: 
	${CC} -o $@ $@.c -lssl -lcrypto
	./sign-file -d sha256 ./signing_key.pem ./signing_key.x509 test.txt

extract-cert: 
	${CC} -o $@ $@.c -lssl -lcrypto

signing_key.x509: signing_key.pem extract-cert
	./extract-cert ./signing_key.pem ./$@

