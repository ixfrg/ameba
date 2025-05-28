ARCH=arm64


DIR_SRC = src
DIR_BUILD = build
DIR_BIN = bin


BPFTOOL_VERSION = v7.2.0
BPFTOOL_ARCH = $(ARCH)
BPFTOOL_URL = https://github.com/libbpf/bpftool/releases/download/$(BPFTOOL_VERSION)/bpftool-$(BPFTOOL_VERSION)-$(BPFTOOL_ARCH).tar.gz
BPFTOOL_TARGZ_FILE = $(DIR_BIN)/bpftool.tar.gz
BPFTOOL_EXE_FILE = $(DIR_BIN)/bpftool
# Overwrite the variable BPFTOOL_EXE_FILE
BPFTOOL_EXE_FILE = /usr/sbin/bpftool


LIBPF_SO = libbpf.so.1


CLANG_BUILD_BPF_FLAGS = -D__TARGET_ARCH_$(ARCH) -O2 -Wall -target bpf -g -I$(DIR_BUILD) -I$(DIR_SRC) -c
CLANG_BUILD_USER_FLAGS = -Wall -g -I$(DIR_BUILD) -I$(DIR_SRC) -c


BPF_OBJS_EVENTS = $(DIR_BUILD)/accept.bpf.o $(DIR_BUILD)/connect.bpf.o $(DIR_BUILD)/process_namespace.bpf.o
BPF_OBJS_HELPERS = $(DIR_BUILD)/map_helper.bpf.o $(DIR_BUILD)/record_helper.bpf.o $(DIR_BUILD)/event_context.bpf.o
BPF_OBJS_ALL = $(BPF_OBJS_HELPERS) $(DIR_BUILD)/ameba.bpf.o $(BPF_OBJS_EVENTS)

USER_OBJS_ALL = $(DIR_BUILD)/jsonify.o $(DIR_BUILD)/ameba.o


download_bpftool:
# https://github.com/xdp-project/xdp-tutorial/issues/368
	test -f "$(BPFTOOL_TARGZ_FILE)" || \
		wget $(BPFTOOL_URL) -O "$(BPFTOOL_TARGZ_FILE)"
	test -f "$(BPFTOOL_EXE_FILE)" || \
		tar -zxvf "$(BPFTOOL_TARGZ_FILE)" -C $(DIR_BIN)
	test -x "$(BPFTOOL_EXE_FILE)" || \
		chmod +x "$(BPFTOOL_EXE_FILE)"


$(DIR_BUILD):
	@mkdir -p $(DIR_BUILD)


$(DIR_SRC)/common/vmlinux.h: 
	$(BPFTOOL_EXE_FILE) btf dump file /sys/kernel/btf/vmlinux format c > $@


$(DIR_BUILD)/map_helper.bpf.o:
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/bpf/maps/map_helper.bpf.c -o $@


$(DIR_BUILD)/record_helper.bpf.o:
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/bpf/helpers/record_helper.bpf.c -o $@


$(DIR_BUILD)/event_context.bpf.o:
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/bpf/helpers/event_context.bpf.c -o $@


$(DIR_BUILD)/ameba.bpf.o:
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/bpf/ameba.bpf.c -o $@


$(DIR_BUILD)/process_namespace.bpf.o:
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/bpf/events/process_namespace.bpf.c -o $@


$(DIR_BUILD)/connect.bpf.o:
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/bpf/events/connect.bpf.c -o $@


$(DIR_BUILD)/accept.bpf.o:
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/bpf/events/accept.bpf.c -o $@


$(DIR_BUILD)/combined.bpf.o: $(DIR_BUILD) $(DIR_SRC)/common/vmlinux.h $(BPF_OBJS_ALL)
	$(BPFTOOL_EXE_FILE) gen object $@ $(BPF_OBJS_ALL)


$(DIR_BUILD)/ameba.skel.h: $(DIR_BUILD)/combined.bpf.o
	$(BPFTOOL_EXE_FILE) gen skeleton $^ name ameba > $@


$(DIR_BUILD)/jsonify.o:
	clang  $(CLANG_BUILD_USER_FLAGS) $(DIR_SRC)/user/jsonify.c -o $@


$(DIR_BUILD)/ameba.o:
	clang $(CLANG_BUILD_USER_FLAGS) $(DIR_SRC)/user/ameba.c -o $@


$(DIR_BIN)/ameba: $(DIR_BUILD)/ameba.skel.h $(USER_OBJS_ALL)
	clang $(USER_OBJS_ALL) -o $@ -l:$(LIBPF_SO) -lpthread


.PHONY: clean all


clean: 
	-rm -r $(DIR_BUILD)


all: $(DIR_BIN)/ameba

###

# In file included from /usr/include/linux/stat.h:5:
# /usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
# #include <asm/types.h>
# RESOLUTION on x86: sudo apt-get install -y gcc-multilib
# SOURCE: https://github.com/xdp-project/xdp-tutorial/issues/44
# https://github.com/xdp-project/xdp-tutorial/issues/44#issuecomment-554608521
# RESOLUTION on aarch64: ln -s /usr/include/aarch64-linux-gnu/asm /usr/include/asm