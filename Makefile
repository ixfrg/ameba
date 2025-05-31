ARCH=arm64


DIR_SRC = src
DIR_BUILD = build
DIR_BIN = bin

BPF_SKEL_NAME = ameba

# BEGIN: Construction of USER_OBJS_ALL
DIR_SRC_U = $(DIR_SRC)/user
DIR_SRC_U_J = $(DIR_SRC_U)/jsonify
DIR_SRC_U_A = $(DIR_SRC_U)/args

DIR_BUILD_U = $(DIR_BUILD)/user
DIR_BUILD_U_J = $(DIR_BUILD_U)/jsonify
DIR_BUILD_U_A = $(DIR_BUILD_U)/args

USER_OBJS_U = $(DIR_BUILD_U)/ameba.o $(DIR_BUILD_U)/convert_data.o $(DIR_BUILD_U)/writer.o
USER_OBJS_U_J = $(DIR_BUILD_U_J)/core.o $(DIR_BUILD_U_J)/record.o $(DIR_BUILD_U_J)/types.o $(DIR_BUILD_U_J)/control.o
USER_OBJS_U_A = $(DIR_BUILD_U_A)/control.o
USER_OBJS_ALL = $(USER_OBJS_U_J) $(USER_OBJS_U)	$(USER_OBJS_U_A)
# END: Construction of USER_OBJS_ALL


# BEGIN: Construction of BPF_OBJS_ALL
DIR_SRC_B = $(DIR_SRC)/bpf
DIR_SRC_B_E = $(DIR_SRC_B)/events
DIR_SRC_B_H = $(DIR_SRC_B)/helpers

DIR_BUILD_B = $(DIR_BUILD)/bpf
DIR_BUILD_B_E = $(DIR_BUILD_B)/events
DIR_BUILD_B_H = $(DIR_BUILD_B)/helpers

BPF_OBJS_B = $(DIR_BUILD_B)/license.bpf.o
BPF_OBJS_B_E = $(DIR_BUILD_B_E)/accept.bpf.o $(DIR_BUILD_B_E)/connect.bpf.o $(DIR_BUILD_B_E)/process_namespace.bpf.o $(DIR_BUILD_B_E)/send_recv.bpf.o $(DIR_BUILD_B_E)/bind.bpf.o $(DIR_BUILD_B_E)/kill.bpf.o
BPF_OBJS_B_H = $(DIR_BUILD_B_H)/event.bpf.o $(DIR_BUILD_B_H)/datatype.bpf.o $(DIR_BUILD_B_H)/copy.bpf.o $(DIR_BUILD_B_H)/output.bpf.o $(DIR_BUILD_B_H)/map.bpf.o $(DIR_BUILD_B_H)/control.bpf.o
BPF_OBJS_ALL = $(BPF_OBJS_B) $(BPF_OBJS_B_E) $(BPF_OBJS_B_H)
# END: Construction of BPF_OBJS_ALL


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


#download_bpftool:
# https://github.com/xdp-project/xdp-tutorial/issues/368
#	test -f "$(BPFTOOL_TARGZ_FILE)" || \
#		wget $(BPFTOOL_URL) -O "$(BPFTOOL_TARGZ_FILE)"
#	test -f "$(BPFTOOL_EXE_FILE)" || \
#		tar -zxvf "$(BPFTOOL_TARGZ_FILE)" -C $(DIR_BIN)
#	test -x "$(BPFTOOL_EXE_FILE)" || \
#		chmod +x "$(BPFTOOL_EXE_FILE)"

# BPF objs build

$(DIR_SRC)/common/vmlinux.h: 
	$(BPFTOOL_EXE_FILE) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(DIR_BUILD_B)/%.bpf.o: $(DIR_SRC_B)/%.bpf.c 
	@mkdir -p $(@D)
	clang $(CLANG_BUILD_BPF_FLAGS) $^ -o $@

$(DIR_BUILD)/combined.bpf.o: $(DIR_SRC)/common/vmlinux.h $(BPF_OBJS_ALL)
	$(BPFTOOL_EXE_FILE) gen object $@ $(BPF_OBJS_ALL)

$(DIR_BUILD)/ameba.skel.h: $(DIR_BUILD)/combined.bpf.o
	$(BPFTOOL_EXE_FILE) gen skeleton $^ name $(BPF_SKEL_NAME) > $@

# USER objs build

$(DIR_BUILD_U)/%.o: $(DIR_SRC_U)/%.c
	@mkdir -p $(@D)
	clang $(CLANG_BUILD_USER_FLAGS) $^ -o $@

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