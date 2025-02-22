# Detekcia operacneho systemu
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    TARGET := maes_xts.exe
    RM := del /F /Q
    MKDIR := mkdir
    RMDIR := rmdir /S /Q
    SEP := \\
else
    DETECTED_OS := $(shell uname -s)
    TARGET := maes_xts
    RM := rm -f
    MKDIR := mkdir -p
    RMDIR := rm -rf
    SEP := /
endif

CC := gcc
# Zakladne flagy pre vsetky zdrojove subory
CFLAGS := -Wall -Wextra -I.
# SIMD flagy pre BLAKE3
BLAKE3_DEFS := -DBLAKE3_NO_AVX512 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_SSE2

# Add Windows-specific flags and libraries
ifeq ($(DETECTED_OS),Windows)
    CFLAGS += -D_WIN32 -D_CRT_SECURE_NO_WARNINGS
    CFLAGS += -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0601
    # Pridanie potrebnych Windows kniznic
    LDFLAGS += -lbcrypt -lkernel32 -lmsvcrt
endif

# Priecinok pre objektove subory
OBJDIR := .build

# Zdrojove subory
SRCS := maes_xts.c
LIBSRCS := libs$(SEP)micro-AES$(SEP)micro_aes.c \
           libs$(SEP)blake3$(SEP)blake3.c \
           libs$(SEP)blake3$(SEP)blake3_dispatch.c \
           libs$(SEP)blake3$(SEP)blake3_portable.c

# Objektove subory
OBJS := $(SRCS:%.c=$(OBJDIR)$(SEP)%.o)
LIBOBJS := $(LIBSRCS:%.c=$(OBJDIR)$(SEP)%.o)

# Hlavny ciel
$(TARGET): $(OBJDIR) $(OBJS) $(LIBOBJS)
	$(CC) -o $@ $(OBJS) $(LIBOBJS) $(CFLAGS) $(LDFLAGS)

# Vytvorenie priecinkov pre objektove subory
$(OBJDIR):
ifeq ($(DETECTED_OS),Windows)
	@if not exist "$(OBJDIR)\libs\micro-AES" mkdir "$(OBJDIR)\libs\micro-AES"
	@if not exist "$(OBJDIR)\libs\blake3" mkdir "$(OBJDIR)\libs\blake3"
else
	$(MKDIR) $(OBJDIR)/libs/micro-AES
	$(MKDIR) $(OBJDIR)/libs/blake3
endif

# Preklad zdrojovych suborov
$(OBJDIR)$(SEP)%.o: %.c | $(OBJDIR)
	@echo "Prekladam $<..."
	$(CC) $(CFLAGS) $(BLAKE3_DEFS) -c $< -o $@

# Preklad kniznic
$(OBJDIR)$(SEP)libs$(SEP)%.o: libs$(SEP)%.c | $(OBJDIR)
	@echo "Prekladam kniznicu $<..."
	$(CC) $(CFLAGS) $(BLAKE3_DEFS) -c $< -o $@

# Vycistenie projektu
clean:
ifeq ($(DETECTED_OS),Windows)
	@if exist "$(OBJDIR)" $(RMDIR) "$(OBJDIR)"
else
	$(RMDIR) $(OBJDIR) 
endif

.PHONY: clean
