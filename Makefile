# Detekcia operacneho systemu
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    TARGET := maes_xts.exe
    RM := del /F /Q
    MKDIR := mkdir
    RMDIR := rmdir /S /Q
    # SEP pre OS prikazy, interne pouzijeme /
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
# Pridane -g pre debug symboly standardne
CFLAGS := -g -Wall -Wextra -I. -DBLAKE3_NO_AVX512 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_SSE2 -fopenmp
LDLIBS := -lm
# Add -fopenmp for linking if needed, depending on the compiler/linker
LDFLAGS := -fopenmp

# Add Windows-specific flags and libraries
ifeq ($(DETECTED_OS),Windows)
    CFLAGS += -D_WIN32 -D_CRT_SECURE_NO_WARNINGS
    CFLAGS += -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0601
    # Pridanie potrebnych Windows kniznic
    LDFLAGS += -lbcrypt -lkernel32 -lmsvcrt
endif

# Priecinok pre objektove subory (pouzivame /)
OBJDIR := .build

# Zdrojove subory (pouzivame /)
SRCS := maes_xts.c
LIBSRCS := libs/micro-AES/micro_aes.c \
           libs/blake3/blake3.c \
           libs/blake3/blake3_dispatch.c \
           libs/blake3/blake3_portable.c

# Objektove subory (pouzivame /)
OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))
LIBOBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(LIBSRCS))

# Hlavny ciel
$(TARGET): $(OBJS) $(LIBOBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# Vytvorenie priecinkov pre objektove subory
# Upravene pre Windows, aby vytvaralo podadresar
$(OBJDIR):
ifeq ($(DETECTED_OS),Windows)
	@if not exist "$(subst /,\,$(OBJDIR))" $(MKDIR) "$(subst /,\,$(OBJDIR))"
	@if not exist "$(subst /,\,$(OBJDIR)/libs)" $(MKDIR) "$(subst /,\,$(OBJDIR)/libs)"
	@if not exist "$(subst /,\,$(OBJDIR)/libs/micro-AES)" $(MKDIR) "$(subst /,\,$(OBJDIR)/libs/micro-AES)"
	@if not exist "$(subst /,\,$(OBJDIR)/libs/blake3)" $(MKDIR) "$(subst /,\,$(OBJDIR)/libs/blake3)"
else
	$(MKDIR) $(OBJDIR)/libs/micro-AES
	$(MKDIR) $(OBJDIR)/libs/blake3
endif

# Pravidlo pre preklad zdrojovych suborov v hlavnom adresari
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	@echo "Prekladam $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Pravidlo pre preklad kniznic (potrebuje explicitnejsiu cestu)
$(OBJDIR)/libs/micro-AES/%.o: libs/micro-AES/%.c | $(OBJDIR)
	@echo "Prekladam kniznicu $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/libs/blake3/%.o: libs/blake3/%.c | $(OBJDIR)
	@echo "Prekladam kniznicu $<..."
	$(CC) $(CFLAGS) -c $< -o $@


# Vycistenie projektu
clean:
ifeq ($(DETECTED_OS),Windows)
	@if exist "$(subst /,\,$(OBJDIR))" $(RMDIR) "$(subst /,\,$(OBJDIR))"
	@if exist "$(TARGET)" $(RM) "$(TARGET)"
else
	$(RMDIR) $(OBJDIR)
	$(RM) $(TARGET)
endif

.PHONY: clean
