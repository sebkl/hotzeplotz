# Include sensitive/local parameters if present
-include config.mk

.PHONY: all clean deploy

export

# Default target
all: 
	$(MAKE) -C dns

# Clean all
clean:
	$(MAKE) -C dns clean

# Deploy
deploy:
	$(MAKE) -C dns deploy_cf