PREFIX ?= /usr/local
BINDIR  = $(PREFIX)/bin
MANDIR  = $(PREFIX)/share/man/man1

.PHONY: all test install uninstall lint clean

all: test

test:
	python3 -m unittest -v test_grew test_hardening

test-quick:
	python3 -m unittest test_grew test_hardening

# Parses with the Python 3.8 grammar, so a match statement or other newer syntax
# fails here even when the machine running make has a newer Python. A 3.12+
# interpreter would still accept an f-string that reuses its own quote or holds a
# backslash in the braces, and a parenthesised multi-item `with`, so those are
# found from the tokens (TestPython38Syntax). On 3.8-3.11 the parser itself
# rejects them.
lint:
	python3 -m unittest test_hardening.TestPython38Syntax

install: lint
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)
	install -m 755 grew.py $(DESTDIR)$(BINDIR)/grew
	install -m 644 grew.1 $(DESTDIR)$(MANDIR)/grew.1
	@echo "installed to $(BINDIR)/grew"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/grew $(DESTDIR)$(MANDIR)/grew.1

clean:
	rm -rf __pycache__ .pytest_cache build dist *.egg-info
