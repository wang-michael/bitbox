PYPBCDIR = pypbc

all: install-pypbc

pypbc:
	$(MAKE) -C $(PYPBCDIR)

install: install-pypbc

install-pypbc: pypbc
	$(MAKE) install -C $(PYPBCDIR)

clean:
	$(MAKE) clean -C $(PYPBCDIR)

