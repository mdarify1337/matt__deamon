CXX = c++
CXXFLAGS = -Wall -Wextra -Werror -std=c++20 -pthread
SRCDIR = src
DAEMON_SOURCES = $(SRCDIR)/main.cpp $(SRCDIR)/MattDaemon.cpp $(SRCDIR)/TintinReporter.cpp $(SRCDIR)/AuthManager.cpp $(SRCDIR)/Crypto.cpp
CLIENT_SOURCES = $(SRCDIR)/Ben_AFK.cpp $(SRCDIR)/Crypto.cpp
DAEMON_OBJECTS = $(DAEMON_SOURCES:.cpp=.o)
CLIENT_OBJECTS = $(CLIENT_SOURCES:.cpp=.o)
DAEMON_TARGET = Matt_daemon
CLIENT_TARGET = Ben_AFK

LDFLAGS = -lssl -lcrypto -lcurl

all: $(DAEMON_TARGET) $(CLIENT_TARGET)

$(DAEMON_TARGET): $(DAEMON_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(CLIENT_TARGET): $(CLIENT_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

install: all
	sudo cp $(DAEMON_TARGET) /usr/local/bin/
	sudo cp $(CLIENT_TARGET) /usr/local/bin/
	sudo mkdir -p /etc/matt_daemon
	sudo mkdir -p /var/log/matt_daemon
	sudo mkdir -p /var/lock

uninstall:
	sudo rm -f /usr/local/bin/$(DAEMON_TARGET)
	sudo rm -f /usr/local/bin/$(CLIENT_TARGET)

clean:
	rm -f $(DAEMON_OBJECTS) $(CLIENT_OBJECTS)
	sudo rm -f /var/log/matt_daemon/*.log
	sudo rm -f /var/log/matt_daemon/*.log.archived
	sudo rm -f /var/lock/matt_daemon.lock

fclean: clean
	rm -f $(DAEMON_TARGET) $(CLIENT_TARGET)
	rm -f /var/log/matt_daemon/*.log
	rm -f /var/log/matt_daemon/*.log.archived
	rm -f /var/lock/matt_daemon.lock

re: fclean all

test: all
	@echo "Testing daemon startup..."
	sudo ./$(DAEMON_TARGET) &
	@sleep 2
	@echo "Testing client connection..."
	echo -e "admin\nadmin123\n5" | ./$(CLIENT_TARGET)
	@echo "Stopping daemon..."
	sudo pkill $(DAEMON_TARGET) || true

.PHONY: all clean fclean re install uninstall test
