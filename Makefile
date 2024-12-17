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
# Potlacenie vsetkych warningov pre kniznice aj hlavny program
SUPPRESSED := -Wno-unused-parameter -Wno-unused-variable -Wno-format
# SIMD flagy pre BLAKE3
BLAKE3_DEFS := -DBLAKE3_NO_AVX512 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_SSE2

# Priecinok pre objektove subory
OBJDIR := .build

# Zdrojove subory
SRCS := maes_xts.c
LIBSRCS := libs$(SEP)micro-AES$(SEP)micro_aes.c \
           libs$(SEP)blake3$(SEP)blake3.c \
           libs$(SEP)blake3$(SEP)blake3_dispatch.c \
           libs$(SEP)blake3$(SEP)blake3_portable.c \

# Objektove subory
OBJS := $(SRCS:%.c=$(OBJDIR)$(SEP)%.o)
LIBOBJS := $(LIBSRCS:%.c=$(OBJDIR)$(SEP)%.o)

# Hlavny ciel
$(TARGET): $(OBJDIR) $(OBJS) $(LIBOBJS)
	$(CC) -o $@ $(OBJS) $(LIBOBJS) $(CFLAGS) $(SUPPRESSED)

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
	$(CC) $(CFLAGS) $(BLAKE3_DEFS) $(SUPPRESSED) -c $< -o $@

# Preklad kniznic s potlacenymi warningami
$(OBJDIR)$(SEP)libs$(SEP)%.o: libs$(SEP)%.c | $(OBJDIR)
	@echo "Prekladam kniznicu $<..."
	$(CC) $(CFLAGS) $(BLAKE3_DEFS) $(SUPPRESSED) -c $< -o $@

# Vycistenie projektu
clean:
ifeq ($(DETECTED_OS),Windows)
	@if exist "$(OBJDIR)" $(RMDIR) "$(OBJDIR)"
else
	$(RMDIR) $(OBJDIR) 
endif

.PHONY: clean