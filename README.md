
## PKCS#7 签名的 DEMO

* cert.S 通过汇编导入公钥，文件，证书
* sign-file.c 从内核找到的内核模块加密的代码
* main.c CA 注册和校验的 demo

通过 key_type 注册管理 CA 证书，verify_pkcs7_signature 进行签名校验