
SOCKET_EVENT	= socket_event
SOCKET_SERVER	= socket_server
GUARD_DAEMON    = guard_daemon
RAJ_TEST		= rajtest

CXXFLAGS	+= -g -O0 -Wall -W -std=c++11 -lpthread
CXXFLAGS	+= -I..
CXXFLAGS	+= ../libeeh.a

PTHREAD_SUPPORT = -lpthread

.PHONY: all
all:
	$(CXX) socket_event.cpp $(CXXFLAGS) -o $(SOCKET_EVENT) $(PTHREAD_SUPPORT)
	$(CXX) socket_server.cpp $(CXXFLAGS) -o $(SOCKET_SERVER) $(PTHREAD_SUPPORT)
	$(CXX) guard_daemon.cpp  $(CXXFLAGS) -o $(GUARD_DAEMON) $(PTHREAD_SUPPORT)
	$(CXX) rajtest.cpp $(CXXFLAGS) -o $(RAJ_TEST)

.PHONY: clean
clean:
	rm -rf $(SOCKET_EVENT)
	rm -rf $(SOCKET_SERVER)
	rm -rf $(GUARD_DAEMON)
	rm -rf $(RAJ_TEST)
