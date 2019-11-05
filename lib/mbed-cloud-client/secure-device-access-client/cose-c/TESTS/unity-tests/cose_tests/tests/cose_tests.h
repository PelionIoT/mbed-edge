
#ifndef __COSE_TESTS_H__
#define __COSE_TESTS_H__

#ifndef _countof

#define _countof(x) (sizeof(x)/sizeof(x[0]))
#endif

//  encrypt.c

int ValidateEnveloped(const cn_cbor * pControl CBOR_CONTEXT);
int EncryptMessage();
int BuildEnvelopedMessage(const cn_cbor * pControl CBOR_CONTEXT);
int ValidateEncrypt(const cn_cbor * pControl CBOR_CONTEXT);
int BuildEncryptMessage(const cn_cbor * pControl CBOR_CONTEXT);
void Enveloped_Corners(CBOR_CONTEXT_NO_COMMA);
void Encrypt_Corners(CBOR_CONTEXT_NO_COMMA);
void Recipient_Corners(CBOR_CONTEXT_NO_COMMA);


//  sign.c

int ValidateSigned(const cn_cbor * pControl CBOR_CONTEXT);
int SignMessage(CBOR_CONTEXT_NO_COMMA);
int BuildSignedMessage(const cn_cbor * pControl CBOR_CONTEXT);
int ValidateSign0(const cn_cbor * pControl CBOR_CONTEXT);
#ifndef USE_CN_CBOR
/*  This function uses tiny cbor functionality */
int ValidateSign0BufferTinyCbor(const cn_cbor * pControl CBOR_CONTEXT);
#endif
int BuildSign0Message(const cn_cbor * pControl CBOR_CONTEXT);
#ifndef USE_CN_CBOR
/*  This function uses tiny cbor functionality */
int BuildSign0MessageWithCoseBuffer(const cn_cbor * pControl CBOR_CONTEXT);
#endif
void Sign_Corners(CBOR_CONTEXT_NO_COMMA);
void Sign0_Corners(CBOR_CONTEXT_NO_COMMA);


// mac_testc

int ValidateMAC(const cn_cbor * pControl CBOR_CONTEXT);
int MacMessage(CBOR_CONTEXT_NO_COMMA);
int BuildMacMessage(const cn_cbor * pControl CBOR_CONTEXT);
int ValidateMac0(const cn_cbor * pControl CBOR_CONTEXT);
int BuildMac0Message(const cn_cbor * pControl CBOR_CONTEXT);
void MAC_Corners(CBOR_CONTEXT_NO_COMMA);
void MAC0_Corners(CBOR_CONTEXT_NO_COMMA);

#ifdef USE_CBOR_CONTEXT
//  context.c
extern cn_cbor_context * CreateContext(unsigned int iFailPoint);
void FreeContext(cn_cbor_context* pContext);
#endif


//  cose_tests.c
typedef enum {
	Attributes_MAC_protected=1,
	Attributes_MAC0_protected,
	Attributes_Recipient_protected,
	Attributes_Enveloped_protected,
	Attributes_Encrypt_protected,
	Attributes_Sign_protected,
	Attributes_Signer_protected,
	Attributes_Sign0_protected,
} whichSet;

extern int CFails;

int MapAlgorithmName(const cn_cbor * p);
byte * GetCBOREncoding(const cn_cbor * pControl, int * pcbEncoded);
//bool SetAttributes(HCOSE hHandle, const cn_cbor * pAttributes, int which, bool fPublicKey);
cn_cbor * BuildKey(const cn_cbor * pKeyIn, bool fPublicKey);
byte * FromHex(const char * rgch, int cch);
bool SetSendingAttributes(HCOSE hMsg, const cn_cbor * pIn, int base);
bool SetReceivingAttributes(HCOSE hMsg, const cn_cbor * pIn, int base);
bool IsAlgorithmSupported(const cn_cbor * alg);
bool IsAlgorithmSupported_tiny(const uint8_t *alg_buffer, size_t alg_buffer_size);

//
//  Internal macros to make testing easier
//

#define CHECK_RETURN(functionCall, errorReturn, onFailure) \
{	\
	if (!functionCall) onFailure; \
}

#define CHECK_FAILURE(functionCall, errorReturn, onFailure)       \
    { \
        bool bReturn = functionCall;  \
        if (!bReturn) { \
            if (cose_error.err != errorReturn) onFailure; \
        } else if (errorReturn != COSE_ERR_NONE) onFailure; \
    }

#define CHECK_FAILURE_PTR(functionCall, errorReturn, onFailure)       \
    { \
        void * bReturn = functionCall;  \
        if (bReturn == NULL) { \
            if (cose_error.err != errorReturn) onFailure; \
        } else if (errorReturn != COSE_ERR_NONE) onFailure; \
    }

#endif //__COSE_TESTS_H__
