.PHONY: all clean

CC = gcc
CFLAGS = -g -Wall -O3 -std=gnu99 -I$(SRC_DIR) -I$(BUILD_DIR) -pthread -D_GNU_SOURCE
LDFLAGS = -pthread

APPS = $(patsubst %.c,%,$(filter-out apps.c,$(notdir $(wildcard $(SRC_DIR)/$(APP_DIR)/*.c))))
JUNK =

all_SRC = app.c array.c data.c hs.c ntf.c parse.c res.c tf.c
all_HDR = apps/apps.h $(wildcard $(SRC_DIR)/*.h)

SRC_DIR = src
BUILD_DIR = build
APP_DIR = apps
VPATH = $(BUILD_DIR):$(SRC_DIR)

define APP_VARS
ifndef $1_SRC
  $1_SRC = $$(APP_DIR)/$1.c
endif
$1_OBJS = $$(addprefix $$(BUILD_DIR)/,$$($1_SRC:.c=.o))
ALL_DIRS += $$(dir $$($1_OBJS))
HDR += $$($1_HDR)
endef

ALL_DIRS =
HDR =
$(foreach app,all $(APPS),$(eval $(call APP_VARS,$(app))))
DIRS = $(sort $(filter-out .,$(patsubst %/,%,$(ALL_DIRS))))

all: $(APPS) | $(BIN_DIR)

define APP_RULES
$1: $$(all_OBJS) $$($1_OBJS)
	$$(CC) -o $$@ $$^ $$(LDFLAGS)
endef
$(foreach app,$(APPS),$(eval $(call APP_RULES,$(app))))

$(BUILD_DIR)/%.o: %.c $(HDR) | $(DIRS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(DIRS):
	mkdir -p $@

clean:
	rm -rf $(APPS) $(BUILD_DIR) $(JUNK)

