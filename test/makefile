
SOCKET_EVENT	= socket_event
SOCKET_SERVER	= socket_server
RAJ_TEST		= rajtest

CXXFLAGS	+= -g -O0 -Wall -std=c++11 -lpthread
CXXFLAGS	+= -I..
CXXFLAGS	+= ../libeeh.a

PTHREAD_SUPPORT = -lpthread

.PHONY: all
all:
	$(CXX) socket_event.cpp $(CXXFLAGS) -o $(SOCKET_EVENT) $(PTHREAD_SUPPORT)
	$(CXX) socket_server.cpp $(CXXFLAGS) -o $(SOCKET_SERVER) $(PTHREAD_SUPPORT)
	$(CXX) rajtest.cpp $(CXXFLAGS) -o $(RAJ_TEST)

.PHONY: clean
clean:
	rm -rf $(SOCKET_EVENT)
	rm -rf $(SOCKET_SERVER)
	rm -rf $(RAJ_TEST)
