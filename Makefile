all: nsh-traffic-injector

CC = gcc
INCLUDE_DIR = src
CFLAGS = -I$(INCLUDE_DIR)


LIBS = -lm -lpcap
OBJ_DIR = obj

POC_OBJ = nsh-traffic-injector.o
OBJS = $(patsubst %,$(OBJ_DIR)/%,$(POC_OBJ))

$(OBJ_DIR)/%.o: src/%.c $(DEPS)
	@mkdir -p $(@D)
	$(CC) -Wall -g -c -o $@ $< $(CFLAGS)

nsh-traffic-injector: $(OBJS)
	$(CC) -Wall -g -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(OBJ_DIR)/*.o *~ core nsh-traffic-injector
	rm -r $(OBJ_DIR)/
