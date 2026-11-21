.PHONY: check test-unit test-smoke test-vulkan test-win64 test-d3d11 regen-vk clean

check: test-unit test-smoke test-vulkan test-win64 test-d3d11

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

regen-vk:
	python3 tools/gen_vulkan64.py -o runtime/vulkan64_gen.inc

clean:
	rm -rf build
