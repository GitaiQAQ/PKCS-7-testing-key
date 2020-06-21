NAME		:= tm
obj-m		:= $(NAME).o
KDIR 		:= /lib/modules/$(shell uname -r)/build
# KDIR 		:= /lib/modules/4.19.126/build
# KDIR 		:= /lib/modules/4.15.0-30deepin-generic/build

$(NAME)-y	:= main.o cert.o

all: ca test.txt.p7s modules

modules: 
	make -C $(KDIR) M=$(PWD) modules

clean-files := sign-file extract-cert test.txt.p7s signing_key.pem signing_key.x509

clean: 
	-rm -r ca
	make -C $(KDIR) M=$(PWD) clean

# 證書生成環境
ca:
	mkdir ca
	touch ca/index.txt
	echo "00" > ca/serial

# CA 證書
cacert.pem: 
	openssl req -new -nodes -x509 -config ca.cnf -outform PEM -out cacert.pem -keyout cakey.pem
	openssl verify -CAfile cacert.pem cacert.pem

cacert.crt: cacert.pem
	openssl x509 -outform der -in cacert.pem -out cacert.crt

# 籤發的證書鏈
cert.pem: cacert.pem
	openssl req -new -nodes -config ca.cnf -outform PEM -out cert.csr -keyout key.pem
	openssl ca -config ca.cnf -notext -cert cacert.pem -keyfile cakey.pem -in cert.csr -out cert.pem
	rm cert.csr
	openssl verify -CAfile cacert.pem cert.pem

cert.crt: cert.pem
	openssl x509 -outform der -in cert.pem -out cert.crt

clean-files += cacert.pem cert.pem cakey.pem key.pem cert.crt cacert.crt

test.txt:
	echo "HelloWorld" > test.txt

sign-file: 
	${CC} -o $@ $@.c -lssl -lcrypto

test.txt.p7s: test.txt sign-file cacert.crt cert.crt
	# openssl smime -sign -in test.txt -inkey key.pem -outform DER -binary -signer cert.pem -out test.txt.p7s
	./sign-file -d sha256 ./key.pem ./cert.crt test.txt

clean-files += test.txt sign-file test.txt.p7s

test.txt.pkcs7.cert: test.txt.p7s
	openssl pkcs7 -inform der -in test.txt.p7s -out test.txt.pkcs7
	openssl pkcs7 -print_certs -in test.txt.pkcs7 -out test.txt.pkcs7.cert
	
verify: test.txt.pkcs7.cert
	openssl smime -verify -CAfile cacert.pem -binary -inform PEM -in test.txt.pkcs7 -content test.txt -certfile test.txt.pkcs7.cert -nointern > /dev/null

clean-files += test.txt.pkcs7 test.txt.pkcs7.cert