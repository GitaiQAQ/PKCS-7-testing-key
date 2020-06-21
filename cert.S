/* SPDX-License-Identifier: GPL-2.0 */
	.align 8
	.globl system_certificate_list
system_certificate_list:
__cert_list_start:
	.incbin "/home/gitai/hook/.ref/pkcs7test/cacert.crt"
__cert_list_end:

	.align 8
	.globl data
data:
__data_start:
	.incbin "/home/gitai/hook/.ref/pkcs7test/test.txt"
__data_end:

	.align 8
	.globl sign
sign:
__sign_start:
	.incbin "/home/gitai/hook/.ref/pkcs7test/test.txt.p7s"
__sign_end:

	.align 8
	.globl system_certificate_list_size
system_certificate_list_size:
	.quad __cert_list_end - __cert_list_start

	.align 8
	.globl data_size
data_size:
	.quad __data_end - __data_start

	.align 8
	.globl sign_size
sign_size:
	.quad __sign_end - __sign_start
