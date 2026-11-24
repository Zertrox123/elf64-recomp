.PHONY: check test-unit test-smoke test-vulkan test-win64 test-d3d11 test-v8 status regen-vk clean

check: test-unit test-smoke test-vulkan test-win64 test-d3d11 test-v8

test-unit:
	python3 -m unittest discover -s tests -p "test_*.py" -v

test-smoke:
	python3 tests/run_e2e.py smoke64

test-vulkan:
	python3 tests/run_e2e.py vulkan

test-win64:
	python3 tests/run_e2e.py win64

test-d3d11:
	python3 tests/run_e2e.py d3d11

test-v8:
	mkdir -p build
	clang -O1 -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable $(CFLAGS) -Iruntime -I/opt/homebrew/include -I/opt/homebrew/include/SDL2 \
		tests/test_v8_jsc.c runtime/runtime64.c runtime/libc64.c runtime/sdl2_64.c runtime/vulkan64.c \
		runtime/win32_64.c runtime/win32_crt_extra.c runtime/cairo_pango64.c runtime/v8_jsc64.c \
		runtime/dxbc_msl.c runtime/d3d11_metal.m \
		-L/opt/homebrew/lib -lSDL2 -Wl,-framework,Cocoa -framework Metal -framework QuartzCore \
		-framework Foundation -framework CoreGraphics -framework CoreText -framework JavaScriptCore -lm -lpthread -ldl $(LDFLAGS) -o build/test_v8_jsc
	./build/test_v8_jsc

status:
	python3 tools/gen_status.py

regen-vk:
	python3 tools/gen_vulkan64.py -o runtime/vulkan64_gen.inc

clean:
	rm -rf build
