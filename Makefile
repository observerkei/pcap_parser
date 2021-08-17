OBJ = pcap_parser.out
OBJS_PATH = ./
PCAP_FILE_PATH = ./file_pcap
OBJS += $(OBJS_PATH)main.o
OBJS += $(OBJS_PATH)pcap_parser.o

CC = gcc
INCLUDE_PATH = ./

$(OBJ):$(OBJS)
	$(CC) $^ -o $@ -l curl
	ls $(PCAP_FILE_PATH) | xargs -I {} ./$(OBJ) $(PCAP_FILE_PATH)/{}

%.o:%.c
	$(CC) -I $(INCLUDE_PATH) -c $^ -o $@ 

.PHONY:

clean:
	rm $(OBJ) $(OBJS_PATH)*.o 
reset:
	make disclean
	make
