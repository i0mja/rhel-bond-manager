# bond-manager — build, verify and install orchestration.
#
#   make dist        rebuild the committed single-file artifact bond_manager.sh
#   make check-dist  verify bond_manager.sh matches a fresh build of lib/
#   make lint        shellcheck (severity: warning)
#   make test        run the bats suite in tests/ (skipped if absent)
#   make check       check-dist + lint + test
#   make man         validate that docs/bond-manager.8 renders cleanly
#   make install     install script + man page (PREFIX=/usr/local, DESTDIR-aware)

SHELL := bash

PREFIX  ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
MANDIR  ?= $(PREFIX)/share/man/man8

DIST := bond_manager.sh
MAN  := docs/bond-manager.8

.PHONY: all dist check-dist lint test check man install uninstall

all: dist

dist:
	bash build/build.sh

check-dist:
	@tmp="$$(mktemp)"; trap 'rm -f "$$tmp"' EXIT; \
	bash build/build.sh "$$tmp" >/dev/null; \
	if ! cmp -s "$$tmp" "$(DIST)"; then \
	  echo "check-dist: FAIL: $(DIST) is out of sync with the lib/ sources." >&2; \
	  echo "check-dist: run 'make dist' and commit the regenerated $(DIST)." >&2; \
	  exit 1; \
	fi; \
	echo "check-dist: OK ($(DIST) matches a fresh build of lib/)"

# Note: the lib/ modules are one compilation unit — variables defined in one
# module are used in others, so per-module shellcheck drowns in cross-file
# SC2034 false positives. Lint the built artifact instead (it is the exact
# concatenation of the modules), plus the standalone entrypoint/build scripts.
lint:
	shellcheck -x -S warning bin/bond-manager build/build.sh
	@tmp="$$(mktemp)"; trap 'rm -f "$$tmp"' EXIT; \
	bash build/build.sh "$$tmp" >/dev/null; \
	shellcheck -S warning "$$tmp"; \
	echo "lint: OK (bin/bond-manager, build/build.sh, built artifact)"

# tests/ is wired but may not exist yet (the suite lives in its own change).
test:
	@if [ -d tests ]; then \
	  bats -r tests; \
	else \
	  echo "test: tests/ directory not present — skipping"; \
	fi

check: check-dist lint test

man:
	@if command -v groff >/dev/null 2>&1; then \
	  out="$$(groff -man -Tutf8 -ww -z "$(MAN)" 2>&1)"; \
	  if [ -n "$$out" ]; then \
	    echo "$$out" >&2; \
	    echo "man: FAIL: groff reported warnings for $(MAN)" >&2; \
	    exit 1; \
	  fi; \
	  echo "man: OK ($(MAN) renders cleanly)"; \
	elif man --warnings -l "$(MAN)" >/dev/null 2>&1; then \
	  echo "man: OK ($(MAN) renders via man)"; \
	else \
	  echo "man: no usable groff/man found — skipping validation"; \
	fi

install:
	install -d "$(DESTDIR)$(SBINDIR)" "$(DESTDIR)$(MANDIR)"
	install -m 0755 "$(DIST)" "$(DESTDIR)$(SBINDIR)/bond-manager"
	install -m 0644 "$(MAN)" "$(DESTDIR)$(MANDIR)/bond-manager.8"

uninstall:
	rm -f "$(DESTDIR)$(SBINDIR)/bond-manager" "$(DESTDIR)$(MANDIR)/bond-manager.8"
