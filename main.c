#include <stdio.h>
#include <stdint.h>

#include "pcapparser.h"


int test_hook(char *hdr, const uint8_t *data, uint16_t len, uint8_t dir)
{
	printf("test:len(%4u)[%u]\t\t", len, dir);

	return 0;
}

int main(int argc, char const* argv[])
{
	if (argc != 2) {
		fprintf(stderr, "use ./app pcap_filename\n");
		return -1;
	}
	return pcap_parser(argv[1], test_hook, NULL);
}
