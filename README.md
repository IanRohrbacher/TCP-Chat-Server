# TCP Chat Server

Multi-threaded TCP chat server and client with role-based command access.

> Created, ran, and tested on Kent State University's viper/adder server.

This project implements a small chat system in C++17 with a server binary (`server.run`) and a client binary (`client.run`). It demonstrates socket programming, select()-based I/O, multi-threading, simple protocol framing, JSON-based configuration (admins & whitelist), and a basic role-based administration model with sudo-style privilege escalation.

## Features

- Username-based client connections with uniqueness validation
- Simultaneous send/receive on the client (multi-threaded)
- Direct messaging (/msg) and broadcast messaging
- Role-based admin commands and session admins via `/sudo` and `/sudo su`
- Configurable admin list and whitelist using JSON files
- Inactivity timeouts for clients and server
- Console (server operator) commands for administration and control
- Thread-safe logging to `logs/` with timestamped files

## Project layout

- `server/` - server-side sources (e.g. `server.cpp`, acceptor, handlers)
- `client/` - client-side sources (e.g. `client.cpp`, send/receive threads)
- `common/` - shared protocol, commands, JSON config helpers, message builders
- `logs/` - runtime server logs (created at server start)
- `admin_config.json` - admin configuration file (username/password pairs)
- `whitelist_config.json` - optional connection whitelist
- `makefile` - simple build script to produce `server.run` and `client.run`

## Requirements

- Linux (project built/tested in a Unix-like environment)
- g++ with C++17 support
- Make (or build using the included Makefile)

Note: The project uses the single-file `nlohmann/json.hpp` library (included in `common/`), so there are no external package-manager dependencies.

## Build

From the project root run one of the following `make` targets.

Build both binaries:

```bash
make        # builds both server.run and client.run
make build  # alias for `make`
```

Build only the server or only the client:

```bash
make build-server   # builds server.run
make build-client   # builds client.run
```

Cleaning targets:

```bash
make clean          # removes the built binaries (server.run, client.run)
make clean-logs     # removes log files under logs/ (e.g. logs/*.log)
```

## Running the server

Start the server in a terminal:

```bash
make server || ./server.run
```

The server listens on TCP port 8080 by default. It will create timestamped logs under `logs/`.

Important configuration files:

- `admin_config.json` — stores `root_password` and an `admins` list. The server initializes the admin system on start and may prompt the operator to set or confirm the root password.
- `whitelist_config.json` — when enabled (`"enabled": true`) only users listed in `users` are allowed to connect.

See the logs (e.g. `logs/Server-YYYY-MM-DD_HH-MM-SS-log.txt`) for status, connections, and admin operations.

## Running the client

Start the client in another terminal and follow the prompts to enter a username and connect to the server:

```bash
make client || ./client.run
```

The client implements two threads: a receive thread (listens for server messages and handles password prompts or kick/ shutdown events) and a send thread (reads user input and sends commands/messages to the server).

## Protocol overview

Messages use a simple framed protocol. Each message begins with a fixed-length header in the format `[XXXX]` (6 bytes including brackets). Examples:

- `[RESP]` — server response / info
- `[USER]` — user message header
- `[PASS]` — password embedded in admin commands

Utilities in `common/` include message building/parsing helpers and a `common_protocol.hpp` that documents header lengths and timeout constants.

## Commands

Commands are prefixed with `/`. The command prefix can be found and changed in `common/common_commands.hpp` -> `COMMAND_PREFIX`.

Client commands (examples):

- `/help` — display help text
- `/quit` — gracefully disconnect
- `/list` — request list of connected users and roles
- `/msg <user> <message>` — send a direct message

Admin-related commands (require admin or `/sudo <cmd> <password>`):

- `/sudo <command> <password>` — run a single admin command by providing the password
- `/sudo su <password>` — become a session admin for the current session
- `/timeout <minutes>` — change client inactivity timeout
- `/servertimeout <minutes>` — change server shutdown timeout
- `/whitelist ...` — manage whitelist (whitelist_config.json)
- `/admin ...` — manage persistent admin list (admin_config.json)
- `/close <user1,user2>` — disconnect listed clients
- `/closeall` — disconnect all clients
- `/shutdown` — shut down the server

Note: The exact commands and mapping are implemented in `common/common_commands.hpp` and handled on the server while only requested by the client.

## Configuration files

- `admin_config.json` (example):

```json
{
	"admins": [],
	"root_password": "root123"
}
```

- `whitelist_config.json` (example):

```json
{
	"enabled": false,
	"users": []
}
```

The project reads/writes these JSON files via helpers in `common/common_json_management.hpp`.

## Logs

Server logs are written to the `logs/` directory with timestamps. Example entries show connections, auth success/fail, admin actions, and shutdown/cleanup events.

## License

The code in this project is licensed under the MIT license.
