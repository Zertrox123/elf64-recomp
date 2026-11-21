.PHONY: check test-unit test-smoke test-vulkan regen-vk clean

check: test-unit test-smoke test-vulkan

test-unit:
	python3 -m unittest discover -s tests -p "test_*.py" -v

test-smoke:
	python3 tests/run_e2e.py smoke64

test-vulkan:
	python3 tests/run_e2e.py vulkan

regen-vk:
	python3 tools/gen_vulkan64.py -o runtime/vulkan64_gen.inc

clean:
	rm -rf build
