#ifndef __PCAP_PARSER_H__
#define __PCAP_PARSER_H__

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

typedef int (*parser_docker_t)(char *, const uint8_t *, uint16_t, uint8_t);

/**
  * 功能：将pcap_file文件解析成数据流，传给解析处理回调接口hook
  * 参数：	
  *		pcap_file 需要解析的pcap包
  *		hook 回调函数
  *		hook_hdr 回调参数传入的第一个参数
  *	返回值：
  *		成功返回  0
  *		失败返回 -1
  */
extern int pcap_parser(const char *pcap_file, parser_docker_t hook, char *hook_hdr);

#ifdef __cplusplus
}
#endif//__cplusplus

#endif//__PCAP_PARSER_H__
