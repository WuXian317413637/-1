//
//  ViewController.m
//  密钥证书进行加密
//
//  Created by 赵存伟 on 15/5/25.
//  Copyright (c) 2015年 buybal. All rights reserved.
//

#import "ViewController.h"
#import "Base64.h"
#import "RSAEncryptor.h"
#import "AFNetworking.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@interface ViewController (){
    
    RSAEncryptor * ras;
    
    NSString * encryptedstring;
}

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.view.backgroundColor = [UIColor whiteColor];
    
    
    
    
    UIButton * button = [UIButton buttonWithType:UIButtonTypeCustom];
    
    button.frame = CGRectMake(100, 100, 100, 100);
    
    [button setTitle:@"Start" forState:UIControlStateNormal];
    
    [button addTarget:self action:@selector(ButtonClick) forControlEvents:UIControlEventTouchUpInside];
    
    [button setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    
    [self.view addSubview:button];
    
    UIButton * decryptionButton = [UIButton buttonWithType:UIButtonTypeCustom];
    decryptionButton.frame = CGRectMake(100, 300, 100, 100);
    [decryptionButton setTitle:@"Decryption" forState:UIControlStateNormal];
    [decryptionButton setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    [decryptionButton addTarget:self action:@selector(decryption) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:decryptionButton];
}

//加密
- (void)ButtonClick{
    
    //创建rsa对象
     ras = [[RSAEncryptor alloc]init];
    
    //读取本地公钥证书
    NSString * publicKeyPath = [[NSBundle mainBundle] pathForResource:@"100" ofType:@"crt"];
    
    //rsa对象加载读取公钥
    [ras loadPublicKeyFromFile:publicKeyPath];
    
    NSString * securitytext = @"hello";
    //让rsa以当前公钥加密字符串hello
    encryptedstring = [ras rsaEncryptString:securitytext];
    
    NSLog(@"encryptedstring is %@, bytes is %ld",encryptedstring,(sizeof(encryptedstring)));
}

//解密
- (void)decryption{
    
    ras = [[RSAEncryptor alloc]init];
    
    NSString * str = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"100.key" ofType:@"p8"] encoding:NSUTF8StringEncoding error:nil];
    
    NSLog(@"str is %@  longed is %ld",str,(sizeof(str)));
    
    NSData * data = [NSData dataWithBase64EncodedString:str];
    NSLog(@"data is %@",data);
    NSString * datastr = [[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];
    NSLog(@"datastr is %@",datastr);
    [ras loadPrivateKeyFromData:data password:@""];
    
    NSString * decryptionStr = [ras rsaDecryptString:encryptedstring];
    NSLog(@"decryptionStr is %@",decryptionStr);
    
}
@end
