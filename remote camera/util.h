#pragma once

#ifndef SHA1_DIGEST_SIZE
#define SHA1_DIGEST_SIZE 20
#endif

void DumpBytes(const UCHAR* pb, ULONG cb, PCSTR msg );

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_ ULONG _cb = 0, _In_ ULONG cb_ = 0);

NTSTATUS Hmac2(_In_ PCWSTR pszAlgId,
			   _In_ PUCHAR pbCV,
			   _In_ ULONG cbCV,
			   _In_ PUCHAR pbInput1, 
			   _In_ ULONG cbInput1, 
			   _In_ PUCHAR pbInput2, 
			   _In_ ULONG cbInput2, 
			   _Out_ PBYTE pbHash, 
			   _In_ ULONG cbHash);

NTSTATUS ImportPublicKey(_Out_ BCRYPT_KEY_HANDLE *phKey, _In_ PCWSTR pszAlgId, _In_ PBYTE pbKey, _In_ ULONG cbKey);

HRESULT GetPublicKeyFromCert(_Out_ BCRYPT_KEY_HANDLE* phKey, 
							 _In_ const BYTE *pbCertEncoded, 
							 _In_ DWORD cbCertEncoded, 
							 _In_ ULONG dwFlags);

HRESULT GetPrivateKeyFromCert(_In_ BOOL bSign, _In_ PCCERT_CONTEXT pCertContext, _Out_ BCRYPT_KEY_HANDLE* phKey);

NTSTATUS GetAlgorithmName(_In_ BCRYPT_KEY_HANDLE hKey, _Out_ PWSTR pszAlgId, _In_ ULONG cb);

BOOL IsSupportedAlg(_In_ PCRYPT_ALGORITHM_IDENTIFIER Algorithm, _Out_ PCWSTR *ppszEccAlgId);

NTSTATUS CFBXcrypt(_In_ PUCHAR pbSymKey, _In_ ULONG cbSymKey, _In_ PBYTE pb, _In_ ULONG cb, _Out_ PBYTE pbOut, _In_ BOOL bDecrypt);

inline NTSTATUS CFBXcrypt(_In_ PUCHAR pbSymKey, _In_ ULONG cbSymKey, _In_ PBYTE pb, _In_ ULONG cb, _In_ BOOL bDecrypt)
{
	return CFBXcrypt(pbSymKey, cbSymKey, pb, cb, pb, bDecrypt);
}

HRESULT ValidateCert(_In_ PCCERT_CONTEXT pCertContext, _In_ PCSTR szUsageIdentifier);

void reverse(PBYTE pb, ULONG cb );

NTSTATUS GetKeyBlockLength(_In_ BCRYPT_KEY_HANDLE hKey, _Out_ PULONG BlockLength);

HRESULT PFXImport(_In_ BOOL bSign, 
				  _In_ PCWSTR lpFileName,
				  _In_ PCWSTR szPassword,
				  _Out_ BCRYPT_KEY_HANDLE* phKey,
				  _Out_opt_ PCCERT_CONTEXT* ppCertContext = 0,
				  _Out_writes_bytes_opt_(SHA1_DIGEST_SIZE) PBYTE pbHash = 0);

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phAesKey, _In_ BCRYPT_KEY_HANDLE hPrivKey, _In_ BCRYPT_KEY_HANDLE hPubKey);

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
				   _In_ BCRYPT_ALG_HANDLE hAlgorithm,
				   _In_ PBYTE pbSecret, 
				   _In_ ULONG cbSecret, 
				   _In_ PCWSTR ChainingMode,
				   _In_opt_ ULONG MessageBlockLength = 0);

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
				   _In_ PBYTE pbSecret, 
				   _In_ ULONG cbSecret, 
				   _In_ PCWSTR ChainingMode,
				   _In_opt_ ULONG MessageBlockLength = 0);

NTSTATUS CreateKeyPairKey(_In_ BCRYPT_KEY_HANDLE *phKey, PCWSTR pszAlgId, ULONG dwLength = 0);

NTSTATUS TransformEccKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
						 _In_ BCRYPT_KEY_HANDLE hKey, 
						 _In_ PCWSTR pszAlgId,
						 _In_ PCWSTR pszBlobType);

NTSTATUS BKeyToNkey(_In_ BOOL bSign,
					_In_ BCRYPT_KEY_HANDLE hKey,
					_In_ PCWSTR pszKeyName, 
					_In_opt_ ULONG dwFlags = 0, 
					_In_opt_ ULONG ExportFlags = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG);