# Detekcia operacneho systemu
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    TARGET := maes_xts.exe
    RM := rm -f 
    MKDIR := mkdir -p 
    RMDIR := rm -rf 
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
CFLAGS := -Wall -Wextra -I. -DBLAKE3_NO_AVX512 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_SSE2
LDLIBS := -lm

# Pridame Windows-specificke flagy a kniznice
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
LIBSRCS := libs/micro-AES/micro_aes.c \
           libs/blake3/blake3.c \
           libs/blake3/blake3_dispatch.c \
           libs/blake3/blake3_portable.c

# Objektove subory
OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))
LIBOBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(LIBSRCS))

all: build-clean

# Pravidlo pre zostavenie a nasledne automaticke vycistenie
build-clean: $(TARGET)
	@echo "Uspesne zostavene. Cistim build priecinok..."
	@$(MAKE) clean-build 

# Hlavny ciel
$(TARGET): $(OBJS) $(LIBOBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# Vytvorenie adresarov pre build
$(OBJDIR):
ifeq ($(DETECTED_OS),Windows)
	@echo Vytvaram adresare pre Windows
else
	@echo Vytvaram adresare pre Linux/Unix...
endif
	$(MKDIR) $(OBJDIR)/libs/micro-AES
	$(MKDIR) $(OBJDIR)/libs/blake3

# Pravidla pre preklad
# Pravidlo pre preklad zdrojovych suborov v hlavnom adresari
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	@echo "Prekladam $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Pravidlo pre preklad kniznic
$(OBJDIR)/libs/micro-AES/%.o: libs/micro-AES/%.c | $(OBJDIR)
	@echo "Prekladam kniznicu $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/libs/blake3/%.o: libs/blake3/%.c | $(OBJDIR)
	@echo "Prekladam kniznicu $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Vycistenie projektu
clean: clean-build
	@echo "Odstranujem cielovy subor: $(TARGET)"
	-$(RM) $(TARGET)

# Ciastocne cistenie - len build priecinok
clean-build:
ifeq ($(DETECTED_OS),Windows)
	@echo Cistim build priecinok pre Windows
	-$(RMDIR) $(subst /,$(SEP),$(OBJDIR))
else
	@echo Cistim build priecinok pre Linux/Unix...
	-$(RMDIR) $(OBJDIR)
endif

.PHONY: clean all build-clean clean-build-only
