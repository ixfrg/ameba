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


default: all


download_bpftool:
# https://github.com/xdp-project/xdp-tutorial/issues/368
	test -f "$(BPFTOOL_TARGZ_FILE)" || \
		wget $(BPFTOOL_URL) -O "$(BPFTOOL_TARGZ_FILE)"
	test -f "$(BPFTOOL_EXE_FILE)" || \
		tar -zxvf "$(BPFTOOL_TARGZ_FILE)" -C $(DIR_BIN)
	test -x "$(BPFTOOL_EXE_FILE)" || \
		chmod +x "$(BPFTOOL_EXE_FILE)"


build_setup:
	@mkdir -p $(DIR_BUILD)
	@mkdir -p $(DIR_BIN)


btf:
	$(BPFTOOL_EXE_FILE) btf dump file /sys/kernel/btf/vmlinux format c > $(DIR_BUILD)/vmlinux.h
	@cp $(DIR_BUILD)/vmlinux.h $(DIR_SRC)/vmlinux.h


bpf_obj:
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/ameba.bpf.c -o $(DIR_BUILD)/ameba.bpf.o
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/connect.bpf.c -o $(DIR_BUILD)/connect.bpf.o
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/accept.bpf.c -o $(DIR_BUILD)/accept.bpf.o
	clang $(CLANG_BUILD_BPF_FLAGS) $(DIR_SRC)/process_namespace.bpf.c -o $(DIR_BUILD)/process_namespace.bpf.o

# In file included from /usr/include/linux/stat.h:5:
# /usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
# #include <asm/types.h>
# RESOLUTION on x86: sudo apt-get install -y gcc-multilib
# SOURCE: https://github.com/xdp-project/xdp-tutorial/issues/44
# https://github.com/xdp-project/xdp-tutorial/issues/44#issuecomment-554608521
# RESOLUTION on aarch64: ln -s /usr/include/aarch64-linux-gnu/asm /usr/include/asm


skel:
	$(BPFTOOL_EXE_FILE) gen object \
		$(DIR_BUILD)/combined.bpf.o \
		$(DIR_BUILD)/ameba.bpf.o \
		$(DIR_BUILD)/connect.bpf.o \
		$(DIR_BUILD)/accept.bpf.o \
		$(DIR_BUILD)/process_namespace.bpf.o
	$(BPFTOOL_EXE_FILE) gen skeleton $(DIR_BUILD)/combined.bpf.o name ameba > $(DIR_BUILD)/ameba.skel.h


bpf_loader:
	clang -Wall -g -I$(DIR_BUILD) $(DIR_SRC)/jsonify_record.c $(DIR_SRC)/ameba.c -o $(DIR_BIN)/ameba -l:$(LIBPF_SO) -lpthread


all: build_setup btf bpf_obj skel bpf_loader


clean: 
	rm -rf $(DIR_BUILD)
