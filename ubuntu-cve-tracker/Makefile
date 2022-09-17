# To test this Makefile, just run "export TARGET=/path/to/output" before
# running "make" and output will be generated there. To test flavors output,
# also run "export SUPPORT_DB=/pat/to/json/support/db" and run "make".
#
# If you set the UCT and UCT_REVIEWED environment variables, then only the
# scripts from the UCT_REVIEWED directory will be used (using the data from the
# UCT directory).

SCRIPTS_RELDIR=/scripts
UCT_SCRIPTS=$(shell pwd)$(SCRIPTS_RELDIR)
ifneq ($(UCT_REVIEWED)$(SCRIPTS_RELDIR),$(SCRIPTS_RELDIR))
	UCT_SCRIPTS=$(UCT_REVIEWED)$(SCRIPTS_RELDIR)
endif
export SCRIPTS=$(UCT_SCRIPTS)
export ACTIVE=$(shell pwd)/active

all: cves pkgs tables

prep:
	rsync -a $(SCRIPTS)/html/top/. $(TARGET)/

cves: prep
	$(MAKE) -C active
	$(MAKE) -C retired
	$(MAKE) -C ignored

pkgs: prep
	# Always regenerate the pkgs makefile, the next call will sort out
	# what has or has not changed.
	$(SCRIPTS)/generate-pkgs-makefile.py > $(TARGET)/.pkgs-makefile
	$(MAKE) -f $(TARGET)/.pkgs-makefile

tables: prep
	if [ -e "$(SUPPORT_DB)" ]; then \
		$(SCRIPTS)/html-report -d $(TARGET) -D $(SUPPORT_DB) ; \
		$(SCRIPTS)/html-report -d $(TARGET) -S -D $(SUPPORT_DB) ; \
	else \
		$(SCRIPTS)/html-report -d $(TARGET) ; \
		$(SCRIPTS)/html-report -d $(TARGET) -S ; \
		$(SCRIPTS)/extra-reports $(TARGET) ; \
	fi \

.PHONY: prep cves pkgs tables

# this target is used for setting up the git tree in a developer's
# environment
dev_setup:
	# install git commit hooks in UCT AND UST. First verify pyflakes3 is installed in the system
	@if ! dpkg -l | grep pyflakes3 -c >>/dev/null; then \
		echo '*** pyflakes3 package is not installed. Please install it and run dev_setup again ***'; \
	else \
		# install git commit hooks in UCT repo \
		echo install -m 755 -b -S .backup scripts/git-hooks/pre-commit-wrapper .git/hooks/pre-commit ; \
		install -m 755 -b -S .backup scripts/git-hooks/pre-commit-wrapper .git/hooks/pre-commit ; \
		echo install -m 755 -b -S .backup scripts/git-hooks/pre-commit .git/hooks/pre-commit-syntax-check ; \
		install -m 755 -b -S .backup scripts/git-hooks/pre-commit .git/hooks/pre-commit-syntax-check ; \
		echo install -m 755 -b -S .backup scripts/git-hooks/pre-commit-pyflakes3 .git/hooks ; \
		install -m 755 -b -S .backup scripts/git-hooks/pre-commit-pyflakes3 .git/hooks ; \
		echo install -m 755 -b -S .backup scripts/git-hooks/pre-commit-emacs .git/hooks ; \
		install -m 755 -b -S .backup scripts/git-hooks/pre-commit-emacs .git/hooks ; \
		# install git prepare message hook; this is used to do a \
		# check-syntax run for merge commits, which the regular git \
		# commit hook mind-bogglingly does not get run on \
		echo install -m 755 -b -S .backup scripts/git-hooks/prepare-commit-msg .git/hooks ; \
		install -m 755 -b -S .backup scripts/git-hooks/prepare-commit-msg .git/hooks ; \
		# install git commit hooks in UST repo if configured \
		if [ -n "$${UST}" ] ; then \
			echo install -m 755 -b -S .backup scripts/git-hooks/pre-commit-pyflakes3 "$${UST}/.git/hooks/pre-commit" ; \
			install -m 755 -b -S .backup scripts/git-hooks/pre-commit-pyflakes3 "$${UST}/.git/hooks/pre-commit" ; \
		else \
		        echo '*** $$UST is not set, unable to install pre commit hooks into UST ***' ; \
		fi \
	fi
	#setup the launchpadlib helper tool symlink
	@if [ -n "$${UQT}" ] ; then \
		echo ln -sf  "$${UQT}/common/lpl_common.py" scripts/lpl_common.py ; \
		ln -sf  "$${UQT}/common/lpl_common.py" scripts/lpl_common.py ; \
	else \
	        echo '*** $$UQT is not set, unable to find location of lpl_common.py ***' ; \
	fi

check:
	$(SCRIPTS)/check-syntax

.PHONY: dev_setup check
