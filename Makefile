# SPDX-License-Identifier: GPL-3.0-or-later
# AMEBA - A Minimal eBPF-based Audit: an eBPF-based Linux telemetry collection tool.
# Copyright (C) 2025  Hassaan Irshad
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
	TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
	TARGET_ARCH := arm64
else
	TARGET_ARCH := $(ARCH)
endif

FLAG_INCLUDE_TASK_CTX_ID := -DINCLUDE_TASK_CTX_ID

DIR_SRC := src
DIR_BUILD := build
DIR_BIN := bin

BPF_SKEL_NAME := ameba


USER_SRC_DIR := $(DIR_SRC)/user
USER_BUILD_DIR := $(DIR_BUILD)/user
USER_SRC_FILES := $(shell find $(USER_SRC_DIR) -name "*.c" -type f)
USER_OBJS_ALL := $(patsubst $(DIR_SRC)/%.c,$(DIR_BUILD)/%.o,$(USER_SRC_FILES))

BPF_SRC_DIR := $(DIR_SRC)/bpf
BPF_BUILD_DIR := $(DIR_BUILD)/bpf
BPF_SRC_FILES := $(shell find $(BPF_SRC_DIR) -name "*.c" -type f)
BPF_OBJS_ALL := $(patsubst $(DIR_SRC)/%.c,$(DIR_BUILD)/%.o,$(BPF_SRC_FILES))

UTILS_SRC_DIR := $(DIR_SRC)/utils
UTILS_BIN_DIR := $(DIR_BIN)/utils
UTILS_SRC_FILES := $(shell find $(UTILS_SRC_DIR) -name "*.c" -type f)
UTILS_EXES_ALL := $(patsubst $(DIR_SRC)/%.c,$(DIR_BIN)/%.exe,$(UTILS_SRC_FILES))


BPFTOOL_VERSION := v7.2.0
BPFTOOL_ARCH := $(TARGET_ARCH)
BPFTOOL_URL := https://github.com/libbpf/bpftool/releases/download/$(BPFTOOL_VERSION)/bpftool-$(BPFTOOL_VERSION)-$(BPFTOOL_ARCH).tar.gz
BPFTOOL_TARGZ_FILE := $(DIR_BIN)/bpftool.tar.gz
BPFTOOL_EXE_FILE := $(DIR_BIN)/bpftool
# Overwrite the variable BPFTOOL_EXE_FILE
BPFTOOL_EXE_FILE := /usr/sbin/bpftool


LIBPF_SO := libbpf.so.1


CLANG_BUILD_BPF_FLAGS := $(FLAG_INCLUDE_TASK_CTX_ID) -D__TARGET_ARCH_$(TARGET_ARCH) -O2 -Wall -mcpu=v4 -target bpf -g -I$(DIR_BUILD) -I$(DIR_SRC) -c
CLANG_BUILD_USER_FLAGS := $(FLAG_INCLUDE_TASK_CTX_ID) -Wall -g -I$(DIR_BUILD) -I$(DIR_SRC) -c
CLANG_BUILD_UTILS_FLAGS := $(FLAG_INCLUDE_TASK_CTX_ID) -Wall -g -I$(DIR_BUILD) -I$(DIR_SRC)


#download_bpftool:
# https://github.com/xdp-project/xdp-tutorial/issues/368
#	test -f "$(BPFTOOL_TARGZ_FILE)" || \
#		wget $(BPFTOOL_URL) -O "$(BPFTOOL_TARGZ_FILE)"
#	test -f "$(BPFTOOL_EXE_FILE)" || \
#		tar -zxvf "$(BPFTOOL_TARGZ_FILE)" -C $(DIR_BIN)
#	test -x "$(BPFTOOL_EXE_FILE)" || \
#		chmod +x "$(BPFTOOL_EXE_FILE)"


$(BPF_BUILD_DIR)/%.o: $(BPF_SRC_DIR)/%.c
	@mkdir -p $(@D)
	clang $(CLANG_BUILD_BPF_FLAGS) $^ -o $@

$(USER_BUILD_DIR)/%.o: $(USER_SRC_DIR)/%.c
	@mkdir -p $(@D)
	clang $(CLANG_BUILD_USER_FLAGS) $^ -o $@

$(UTILS_BIN_DIR)/%.exe: $(UTILS_SRC_DIR)/%.c
	@mkdir -p $(@D)
	clang $(CLANG_BUILD_UTILS_FLAGS) $^ -o $@

$(DIR_SRC)/common/vmlinux.h: 
	$(BPFTOOL_EXE_FILE) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(DIR_BUILD)/combined.bpf.o: $(DIR_SRC)/common/vmlinux.h $(BPF_OBJS_ALL)
	$(BPFTOOL_EXE_FILE) gen object $@ $(BPF_OBJS_ALL)

$(DIR_BUILD)/ameba.skel.h: $(DIR_BUILD)/combined.bpf.o
	$(BPFTOOL_EXE_FILE) gen skeleton $^ name $(BPF_SKEL_NAME) > $@

bpf_objs: $(BPF_OBJS_ALL) $(DIR_BUILD)/ameba.skel.h

$(DIR_BIN)/ameba: bpf_objs $(USER_OBJS_ALL)
	clang $(USER_OBJS_ALL) -o $@ -l:$(LIBPF_SO) -lpthread


.PHONY: clean all


clean: 
	-rm -r $(DIR_BUILD)


all: $(DIR_BIN)/ameba $(UTILS_EXES_ALL)

###

# In file included from /usr/include/linux/stat.h:5:
# /usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
# #include <asm/types.h>
# RESOLUTION on x86: sudo apt-get install -y gcc-multilib
# SOURCE: https://github.com/xdp-project/xdp-tutorial/issues/44
# https://github.com/xdp-project/xdp-tutorial/issues/44#issuecomment-554608521
# RESOLUTION on aarch64: ln -s /usr/include/aarch64-linux-gnu/asm /usr/include/asm