CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra

SERVER_SRC := server/server.cpp
CLIENT_SRC := client/client.cpp

SERVER_BIN := server.run
CLIENT_BIN := client.run
.PHONY: all server client clean $(SERVER_BIN) $(CLIENT_BIN) \
	build build-server build-client clean-logs

# Logs
LOG_DIR := logs
LOG_GLOB := $(LOG_DIR)/*.log

all: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Convenience build targets
# `make build` builds both binaries.
# `make build-server` and `make build-client` build only the requested binary.
build: $(SERVER_BIN) $(CLIENT_BIN)

build-server: $(SERVER_BIN)

build-client: $(CLIENT_BIN)

server: $(SERVER_BIN)
	@./$(SERVER_BIN) || true

client: $(CLIENT_BIN)
	@./$(CLIENT_BIN) || true

clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN)

# Remove log files under $(LOG_DIR)
clean-logs:
	rm -f $(LOG_GLOB)