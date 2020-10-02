
SOCKET_EVENT    = socket_event
SOCKET_SERVER	= socket_server
GUARD_DAEMON    = guard_daemon


CXXFLAGS	+= -g -O0 -Wall -W -std=c++11 -lpthread
CXXFLAGS	+= -I..
CXXFLAGS	+= ../libeeh.a

PTHREAD_SUPPORT = -lpthread

.PHONY: all
all:
	$(CXX) socket_event.cpp bic.cpp $(CXXFLAGS) -o $(SOCKET_EVENT) $(PTHREAD_SUPPORT)
	$(CXX) socket_server.cpp bic.cpp $(CXXFLAGS) -o $(SOCKET_SERVER) $(PTHREAD_SUPPORT)
	$(CXX) guard_daemon.cpp bic.cpp $(CXXFLAGS) -o $(GUARD_DAEMON) $(PTHREAD_SUPPORT)

.PHONY: clean
clean:
	rm -rf $(SOCKET_EVENT)
	rm -rf $(SOCKET_SERVER)
	rm -rf $(GUARD_DAEMON)
