# Falcon (FN-DSA), Portierung nach C.
#
#   make test           alle Tests im Debug-Build (AddressSanitizer, UBSan)
#   make test-release   alle Tests optimiert
#   make bench          Laufzeitmessung nach Messprotokoll (Rust/PLAN.md 5.2)
#   make dudect [DIT=1] Zeitmessung zur konstanten Laufzeit (ct/dudect.c)
#   make clean

CC ?= cc
# -ffp-contract=off ist zwingend: Bitgleichheit mit Python verlangt einzeln
# gerundete Gleitkommaoperationen (Ebene 5). Nie -ffast-math.
# -fno-math-errno: sqrt setzt kein errno und verzweigt deshalb nicht (Z2); Ergebnisse unverändert.
BASE_CFLAGS = -std=c11 -Wall -Wextra -Wconversion -Werror -ffp-contract=off -fno-math-errno -Isrc -Itests \
              -DFALCON_DATA_DIR=\"../Python/data\"
DEBUG_CFLAGS = $(BASE_CFLAGS) -O0 -g -fsanitize=address,undefined -fno-sanitize-recover=all
RELEASE_CFLAGS = $(BASE_CFLAGS) -O2

SRC = $(wildcard src/*.c)
SUPPORT = tests/vectors.c
TESTS = $(patsubst tests/%.c,%,$(filter-out $(SUPPORT),$(wildcard tests/test_*.c)))

.PHONY: test test-release bench dudect clean

define RUN_TESTS
	@mkdir -p build/$(1)
	@for t in $(TESTS); do \
	  $(CC) $(2) $(SRC) $(SUPPORT) tests/$$t.c -lm -o build/$(1)/$$t || exit 1; \
	  ./build/$(1)/$$t || exit 1; \
	done
endef

test:
	$(call RUN_TESTS,debug,$(DEBUG_CFLAGS))

test-release:
	$(call RUN_TESTS,release,$(RELEASE_CFLAGS))

bench:
	@mkdir -p build/release
	$(CC) $(RELEASE_CFLAGS) $(SRC) $(SUPPORT) bench/bench.c -lm -o build/release/bench
	./build/release/bench

dudect:
	@mkdir -p build/release
	$(CC) $(RELEASE_CFLAGS) $(if $(DIT),-DFALCON_DIT -march=armv8.4-a) $(SRC) $(SUPPORT) ct/dudect.c -lm \
	  -o build/release/dudect
	./build/release/dudect $(SCALE)

clean:
	rm -rf build
