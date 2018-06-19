all: pcap_to_nsh

CC = gcc
INCLUDE_DIR = src
CFLAGS = -I$(INCLUDE_DIR)


LIBS = -lm -lpcap
OBJ_DIR = obj

POC_OBJ = pcap_to_nsh.o
OBJS = $(patsubst %,$(OBJ_DIR)/%,$(POC_OBJ))

$(OBJ_DIR)/%.o: src/%.c $(DEPS)
	@mkdir -p $(@D)
	$(CC) -Wall -g -c -o $@ $< $(CFLAGS)

pcap_to_nsh: $(OBJS)
	$(CC) -Wall -g -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(OBJ_DIR)/*.o *~ core pcap_to_nsh
	rm -r $(OBJ_DIR)/
