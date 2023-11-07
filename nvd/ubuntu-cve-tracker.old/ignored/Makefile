# Handle per-file CVE export
include ../Makefile.include

# Handle mass-CVE file export
all:: $(TARGET)/.nfus

$(TARGET)/.nfus: not-for-us.txt $(SCRIPTS)/html_export.py $(SCRIPTS)/expand-nfu.py
	$(SCRIPTS)/expand-nfu.py --commit $(GIT_COMMIT) --html $(TARGET) not-for-us.txt
	touch $@
