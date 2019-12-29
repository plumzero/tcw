

SOCKET_EVENT    = socket_event
SOCKET_SERVER   = socket_server

CXXFLAGS    += -g -O0
CXXFLAGS    += -I.
CXXFLAGS    += bic.cpp eehandler.cpp eemodule.cpp eeclient.cpp eehelper.cpp
CXXFLAGS    += -std=c++11
CXXFLAGS    += -lpthread

.PHONY: all
all:
	$(CXX) socket_event.cpp $(CXXFLAGS) -o $(SOCKET_EVENT)
	$(CXX) socket_server.cpp $(CXXFLAGS) -o $(SOCKET_SERVER)

.PHONY: clean
clean:
	rm -rf $(SOCKET_EVENT) $(SOCKET_SERVER)
