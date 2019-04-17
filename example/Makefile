CXX ?= "g++"

all: echo_client echo_server
echo_client: QuicEchoClient.cc
	$(CXX) -std=c++11 -I../src/wrapper -c -o QuicEchoClient.o QuicEchoClient.cc && \
	$(CXX) -o echo_client QuicEchoClient.o -L/home/user/work/quic/qlib -ltestquic
echo_server: QuicEchoServer.cc
	$(CXX) -std=c++11 -I../src/wrapper -c -o QuicEchoServer.o QuicEchoServer.cc && \
	$(CXX) -o echo_server QuicEchoServer.o -L/home/user/work/quic/qlib -ltestquic
clean:
	rm *.o echo_*