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


INSTALL_DIR ?= bin

ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
	TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
	TARGET_ARCH := arm64
else
	TARGET_ARCH := $(ARCH)
endif

##

KERNEL_CONFIG := /boot/config-$(shell uname -r)
OS_NAME := $(shell uname)
OS_KERNEL_MAJOR := $(shell uname -r | cut -d '.' -f 1)
OS_KERNEL_MINOR := $(shell uname -r | cut -d '.' -f 2 | xargs printf "%03d")
OS_KERNEL_NUMBER := $(OS_KERNEL_MAJOR)$(OS_KERNEL_MINOR)
MIN_OS_KERNEL_NUMBER := 6008
MIN_OS_KERNEL_NAME := 6.8

##

FLAG_INCLUDE_TASK_CTX_ID := -DINCLUDE_TASK_CTX_ID

DIR_SRC := src
DIR_BUILD := build
DIR_SRC_C := $(DIR_SRC)/c
DIR_BUILD_C := $(DIR_BUILD)/c
DIR_BIN := bin

BPF_SKEL_NAME := ameba
BIN_NAME := ameba

USER_SRC_DIR := $(DIR_SRC_C)/user
USER_BUILD_DIR := $(DIR_BUILD_C)/user
USER_SRC_FILES := $(shell find $(USER_SRC_DIR) -name "*.c" -type f)
USER_OBJS_ALL := $(patsubst $(DIR_SRC_C)/%.c,$(DIR_BUILD_C)/%.o,$(USER_SRC_FILES))

BPF_SRC_DIR := $(DIR_SRC_C)/bpf
BPF_BUILD_DIR := $(DIR_BUILD_C)/bpf
BPF_SRC_FILES := $(shell find $(BPF_SRC_DIR) -name "*.c" -type f)
BPF_OBJS_ALL := $(patsubst $(DIR_SRC_C)/%.c,$(DIR_BUILD_C)/%.o,$(BPF_SRC_FILES))

UTILS_SRC_DIR := $(DIR_SRC_C)/utils
UTILS_BIN_DIR := $(DIR_BIN)/utils
UTILS_SRC_FILES := $(shell find $(UTILS_SRC_DIR) -name "*.c" -type f)
UTILS_EXES_ALL := $(patsubst $(DIR_SRC_C)/%.c,$(DIR_BIN)/%.exe,$(UTILS_SRC_FILES))


BPFTOOL_VERSION := v7.2.0
BPFTOOL_ARCH := $(TARGET_ARCH)
BPFTOOL_URL := https://github.com/libbpf/bpftool/releases/download/$(BPFTOOL_VERSION)/bpftool-$(BPFTOOL_VERSION)-$(BPFTOOL_ARCH).tar.gz
BPFTOOL_TARGZ_FILE := $(DIR_BIN)/bpftool.tar.gz
BPFTOOL_EXE_FILE := $(DIR_BIN)/bpftool
# Overwrite the variable BPFTOOL_EXE_FILE
BPFTOOL_EXE_FILE := /usr/sbin/bpftool


LIBPF_SO := libbpf.so.1


CLANG_BUILD_BPF_FLAGS := $(FLAG_INCLUDE_TASK_CTX_ID) -D__TARGET_ARCH_$(TARGET_ARCH) -O2 -Wall -mcpu=v4 -target bpf -g -I$(DIR_BUILD_C) -I$(DIR_SRC_C) -c
CLANG_BUILD_USER_FLAGS := $(FLAG_INCLUDE_TASK_CTX_ID) -Wall -g -I$(DIR_BUILD_C) -I$(DIR_SRC_C) -c
CLANG_BUILD_UTILS_FLAGS := $(FLAG_INCLUDE_TASK_CTX_ID) -Wall -g -I$(DIR_BUILD_C) -I$(DIR_SRC_C)


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

$(DIR_SRC_C)/common/vmlinux.h:
	$(BPFTOOL_EXE_FILE) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(DIR_BUILD_C)/combined.bpf.o: $(BPF_OBJS_ALL)
	$(BPFTOOL_EXE_FILE) gen object $@ $(BPF_OBJS_ALL)

$(DIR_BUILD_C)/ameba.skel.h: $(DIR_BUILD_C)/combined.bpf.o
	$(BPFTOOL_EXE_FILE) gen skeleton $^ name $(BPF_SKEL_NAME) > $@

bpf_objs: $(DIR_SRC_C)/common/vmlinux.h $(BPF_OBJS_ALL) $(DIR_BUILD_C)/ameba.skel.h

$(DIR_BIN)/$(BIN_NAME): bpf_objs $(USER_OBJS_ALL)
	clang $(USER_OBJS_ALL) -o $@ -l:$(LIBPF_SO) -lpthread


.PHONY: check_system_requirements clean all install


check_system_requirements:
	@if [ "$(OS_NAME)" = "Linux" ]; then \
		echo "✔ Operation system... Linux"; \
		if grep -q '^CONFIG_BPF_SYSCALL=y' $(KERNEL_CONFIG); then \
			echo "✔ CONFIG_BPF_SYSCALL... enabled"; \
			if [ $(OS_KERNEL_NUMBER) -ge $(MIN_OS_KERNEL_NUMBER) ]; then \
				echo "✔ Kernel... $(MIN_OS_KERNEL_NAME)"; \
			else \
				echo "✖ Kernel must be later than or equal to $(MIN_OS_KERNEL_NAME)"; \
				exit 1; \
			fi \
		else \
			echo "✖ CONFIG_BPF_SYSCALL must be enabled!"; \
			exit 1; \
		fi \
	else \
		echo "✖ Operating system must be Linux"; \
		exit 1; \
	fi


clean: 
	-rm -r $(DIR_BUILD_C)
	-rm $(DIR_BIN)/$(BIN_NAME)


all: check_system_requirements $(DIR_BIN)/$(BIN_NAME) $(UTILS_EXES_ALL)


install:
	@test "$(DIR_BIN)" = "$(INSTALL_DIR)" || \
		{ \
			mkdir -p "$(INSTALL_DIR)" && \
			cp "$(DIR_BIN)/$(BIN_NAME)" "$(INSTALL_DIR)/$(BIN_NAME)" && \
			echo "Installed at: $(INSTALL_DIR)/$(BIN_NAME)"; \
		}

###

# In file included from /usr/include/linux/stat.h:5:
# /usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
# #include <asm/types.h>
# RESOLUTION on x86: sudo apt-get install -y gcc-multilib
# SOURCE: https://github.com/xdp-project/xdp-tutorial/issues/44
# https://github.com/xdp-project/xdp-tutorial/issues/44#issuecomment-554608521
# RESOLUTION on aarch64: ln -s /usr/include/aarch64-linux-gnu/asm /usr/include/asm