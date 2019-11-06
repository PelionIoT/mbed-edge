#pragma once

extern const cn_cbor * ParseJson(const char * fileName);
extern const cn_cbor * ParseString(char * rgch, int ib, int cch);

extern unsigned char *base64_decode(const char *data,	size_t input_length,	size_t *output_length);
