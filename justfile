cc      := "gcc"
cflags  := "-Os -nostdlib -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident"
ldflags := "-fPIC -shared -lc -Wl,-e,_start -Wl,--build-id=none -Wl,-z,norelro -Wl,-z,noseparate-code"

# Build the shared object
all: build

build:
    {{cc}} {{cflags}} suidkick.c -o suidkick {{ldflags}}
    strip suidkick

# Run tests
test: build
    ./suidkick whoami
    LD_PRELOAD=./suidkick RUNC='echo HELLO WORLD && whoami' /bin/echo "real stuff here"

# Remove build artifacts
clean:
    rm -f suidkick