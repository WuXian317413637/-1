//
//  TestController.m
//  密钥证书进行加密
//
//  Created by 赵存伟 on 15/5/27.
//  Copyright (c) 2015年 buybal. All rights reserved.
//

#import "TestController.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#import "Base64.h"
#import <CoreFoundation/CoreFoundation.h>

#define kChosenDigestLength CC_SHA1_DIGEST_LENGTH //SHA-1消息摘要的数据位数160位

@interface TestController ()

@end

@implementation TestController

- (void)viewDidLoad {
    [super viewDidLoad];
   
    self.view.backgroundColor = [UIColor whiteColor];
    
    
    NSString * encryptionStr = [self signTheDataSHA1WithRSA:@"hello"];
    
    NSLog(@"encryptionStr is %@",encryptionStr);
}

- (NSData *)getHashBytes:(NSData *)plainText{
    
    CC_SHA1_CTX ctx;
    
    //uint8_t这个类型是将unsigned char进行一个typedef设置别名
    uint8_t * hashBytes = NULL;
    
    NSData * hash = nil;
    
    //使用malloc获取一个缓冲区存放hash
    //malloc函数的用途：以括号里面的参数大小来分配存储空间
    hashBytes = malloc(kChosenDigestLength * sizeof(uint8_t));
    
    //memset(void * s, int ch, size_t n);作用是将s中前n个字节用ch替换并返回s；作用是在一段内存块中填充某个给定的值，它是对较大的结构体或数组进行清零的最快方法
    memset((void *)hashBytes, 0x0, kChosenDigestLength);
    
    //初始化上下文
    CC_SHA1_Init(&ctx);
    
    CC_SHA1_Update(&ctx, (void*)[plainText bytes], [plainText length]);
    
    CC_SHA1_Final(hashBytes, &ctx);
    
    //Build up the SHA1 blob
    hash = [NSData dataWithBytes:(const void * )hashBytes length:(NSUInteger)kChosenDigestLength];
    
    return hash;
}

//签名
- (NSString *)signTheDataSHA1WithRSA:(NSString *)planText{
    
    uint8_t * signedByts = NULL;
    
    //size_t是一个与机器相关的unsigned类型，其中大小足以保证存储内存中对象的大小
    size_t signedBytessSize = 0;
    
    //OSStatus有符号int类型
    OSStatus sanityCheck = noErr;
    
    NSData * signedHash = nil;
    
    NSString * privateKey = @"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAK67Zh+SsNOz/WFTqnozSlDGoYTjTtDAnjthoci1FHVvNycmo0+bFKMqkyLVc83OYzh6pq47/yF24muTUJp9jaeIdhc+39bOSL14qutTJ+oZsHetMBoH/dTGe9O2iQnlcUZ/tph1jPwi82/gwweqj2mX3QoTpZPxQSsuZOSzZWKVAgMBAAECgYAjCpP9avapTiRXW2cJ4LVbo6oKs2c/+BEDiZ3fWWlD78zYvifsNAacflJJnxL9SBGf5wD8Wi3dMTFRL5bvlJROmZtyebOx9NGfHY1Neo6aTJOy8SRuJ4kq/86vNLy0hix4z9U7+cPj/Mf9XQhIrLlGyJd9OnqL9iCmg6ovrGorQQJBAP0uD+b6OGoSalJ6QfnByk2kXmOaooFyXwbdjUWeYlDjjaTaf/WAU4rcQ6MSFKZtzTdFifdi+FWYUQbr7EO2VaUCQQCwraTg/+a5ERqA7h+4VVZBEkhedQK8YDVQy1jb7kW+kV1hS91OcQOpDmyiji/JmcfQ4J/hNQXn9nCxotx0PqYxAkB3z+KKpgMof0p9eYnbTdAU6iIY9MbOh3dc4l/GgGt6aBVR3G0Nmwrt/cqsUxQepnulGm1t+xIWP5yor+EBMjpZAkBTc0E8kUJ+SWjWWyMaYxxhkewiyWvoZBzqs5GeF/ZTY7/SlA3M3i6XbFu9kCFcPMmXjHGX4v6OKOXj0YQFWA4RAkEAgsM7aI9ebNQe4JIRO8a9dU9YXfb/9HM7yhD+8U/DqBTrhk8SAS3OZvoByUOy96zf+3C3GSeFHW6RhuFtSdPg/A==";
    
    NSData * data = [[NSData alloc]initWithBase64Encoding:privateKey];
    
    NSLog(@"data is %@",data);
    
    //set private key query dictonary
    NSMutableDictionary * option = [[NSMutableDictionary alloc]init];
    
    [option setObject:@"" forKey:(__bridge id)kSecImportExportPassphrase];
    
    //CFArrayRef可以和NSArray相互转换
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    //SecPKCS12Import该函数将pkcs12标准的密钥为参数
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef)data, (__bridge CFDictionaryRef)option, &items);
    
    if (securityError != noErr) {
        return nil;
    }
    
    CFDictionaryRef indentityDict = CFArrayGetValueAtIndex(items, 0);
    
    SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(indentityDict, kSecImportItemIdentity);
    SecKeyRef privateKeyRef = nil;
    
    SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
    
    signedBytessSize = SecKeyGetBlockSize(privateKeyRef);
    
    NSData * plainTextBytes = [planText dataUsingEncoding:NSUTF8StringEncoding];
    
    //malloc一个缓冲区来保存签名
    signedByts = malloc(signedBytessSize * sizeof(uint8_t));
    
    memset((void *)signedByts, 0x0, signedBytessSize);
    
    sanityCheck = SecKeyRawSign(privateKeyRef,kSecPaddingPKCS1SHA1, (const uint8_t *)[[self getHashBytes:plainTextBytes] bytes], kChosenDigestLength,  (uint8_t *)signedByts, &signedBytessSize);
    
    if (sanityCheck == noErr) {
        
        signedHash = [NSData dataWithBytes:(const void*)signedByts length:(NSUInteger)signedBytessSize];
        
    }else{
        
        return nil;
    }
    
    if (signedByts) {
        free(signedByts);
    }
    NSString * signatureResult = [NSString stringWithFormat:@"%@",[signedHash base64EncodedString]];
    return signatureResult;
}

//SecKeyRef为密钥对象
- (SecKeyRef)getPublicKey{
    
    NSString * cerPath = [[NSBundle mainBundle] pathForResource:@"100" ofType:@"crt"];
    
    SecCertificateRef myCertificate = nil;
    
    NSData * certificateData = [[NSData alloc]initWithContentsOfFile:cerPath];
    
    myCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certificateData);
    
    SecPolicyRef myPolicy = SecPolicyCreateBasicX509();
    
    SecTrustRef myTruyst;
    
    OSStatus status = SecTrustCreateWithCertificates(myCertificate, myPolicy, &myTruyst);
    
    SecTrustResultType trustResult;
    
    if (status == noErr) {
        status = SecTrustEvaluate(myTruyst, &trustResult);
    }
    return SecTrustCopyPublicKey(myTruyst);
    
    
}

//解密
-(NSString *)RSAEncrypotoTheData:(NSString *)plainText
{
    
    SecKeyRef publicKey=nil;
    publicKey=[self getPublicKey];
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = NULL;
    
    cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    memset((void *)cipherBuffer, 0*0, cipherBufferSize);
    
    NSData *plainTextBytes = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    int blockSize = cipherBufferSize-11;  // 这个地方比较重要是加密问组长度
    int numBlock = (int)ceil([plainTextBytes length] / (double)blockSize);
    NSMutableData *encryptedData = [[NSMutableData alloc] init];
    for (int i=0; i<numBlock; i++) {
        int bufferSize = MIN(blockSize,[plainTextBytes length]-i*blockSize);
        NSData *buffer = [plainTextBytes subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
        OSStatus status = SecKeyEncrypt(publicKey,
                                        kSecPaddingPKCS1,
                                        (const uint8_t *)[buffer bytes],
                                        [buffer length],
                                        cipherBuffer,
                                        &cipherBufferSize);
        if (status == noErr)
        {
            NSData *encryptedBytes = [[NSData alloc]
                                       initWithBytes:(const void *)cipherBuffer
                                       length:cipherBufferSize];
            [encryptedData appendData:encryptedBytes];
        }
        else
        {
            return nil;
        }
    }
    if (cipherBuffer)
    {
        free(cipherBuffer);
    }
    NSString *encrypotoResult=[NSString stringWithFormat:@"%@",[encryptedData base64EncodedString]];
    return encrypotoResult;
}



@end
