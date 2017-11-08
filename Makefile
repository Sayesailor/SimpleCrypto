OBJS = simple_crypto.o base64_light.o

.SUFFIX:
.SUFFIX: .cc
.cc.o:; g++ -std=c++11 -g -m64 -lcrypto -c $< -o $@

TARGETS = libsimple_crypto.a

all : $(TARGETS)

$(TARGETS) : $(OBJS)
	ar -r $@ $^

clean:
	rm -f *.o *.a
