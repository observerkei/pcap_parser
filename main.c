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

	/**
	 * 给pcap包插入一个结束标志(插入一条拷贝最后一条数据，并置位 fin/res 标志位的空数据)
	 * 视情况使用，有的数据包没有结束标志的时候，如果想添加结束标志，则可以用到这个接口
	tcp_insert_close(); 
	 */

	return pcap_parser(argv[1], test_hook, NULL);
}
