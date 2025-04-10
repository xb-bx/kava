.PHONY: all
all: libHelloWorld.so HelloWorld.class

libHelloWorld.so: *.c *.h
	gcc -g -shared -Wall -Werror -I/usr/lib/jvm/java-8-openjdk/include -I/usr/lib/jvm/java-8-openjdk/include/linux -o libHelloWorld.so -fPIC HelloWorld.c
HelloWorld.class: HelloWorld.java
	javac HelloWorld.java
clean:
	rm -f ./libHelloWorld.so ./HelloWorld.class
