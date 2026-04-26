#include "stdafx.h"

_NT_BEGIN
#include "log.h"
#include "util.h"

void DumpBytes(const UCHAR* pb, ULONG cb, PCSTR msg )
{
	PSTR psz = 0;
	ULONG cch = 0;
	while (CryptBinaryToStringA(pb, cb, CRYPT_STRING_HEXASCIIADDR, psz, &cch))
	{
		if (psz)
		{
			DbgPrint("%hs\r\n%.*hs\r\n", msg, cch, psz);
			break;
		}

		if (!(psz = new CHAR[cch]))
		{
			break;
		}
	}

	if (psz)
	{
		delete [] psz;
	}
}

PWSTR IsRegExpandSz(PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi)
{
	ULONG DataLength = pkvpi->DataLength;
	PWSTR psz = (PWSTR)RtlOffsetToPointer(pkvpi->Data, DataLength - sizeof(WCHAR));

	return pkvpi->Type == REG_EXPAND_SZ && DataLength && 
		!(DataLength & (sizeof(WCHAR) - 1)) && !*psz ? psz : 0;
}

NTSTATUS ExpandName(_In_ PCWSTR name, _Out_ PUNICODE_STRING NtName)
{
	HANDLE hKey;
	NTSTATUS status;
	STATIC_OBJECT_ATTRIBUTES(oa, "\\registry\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders");
	if (0 <= (status = ZwOpenKey(&hKey, KEY_READ, &oa)))
	{
		STATIC_UNICODE_STRING(Common_Documents, "Common Documents");
		PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)
			alloca(wcslen(name)*sizeof(WCHAR) + 514);
		ULONG cb;
		status = ZwQueryValueKey(hKey, &Common_Documents, KeyValuePartialInformationAlign64, pkvpi, 512, &cb);
		NtClose(hKey);
		if (0 <= status)
		{
			if (PWSTR psz = IsRegExpandSz(pkvpi))
			{
				*psz = L'\\';
				wcscpy(psz + 1, name);
				psz = 0, cb = 0;

				while (cb = ExpandEnvironmentStringsW((PWSTR)pkvpi->Data, psz, cb))
				{
					if (psz)
					{
						return RtlDosPathNameToNtPathName_U_WithStatus(psz, NtName, 0, 0);
					}

					psz = (PWSTR)alloca(cb * sizeof(WCHAR));
				}

				return GetLastHresult();

			}

			return STATUS_OBJECT_TYPE_MISMATCH;
		}
	}

	return status;
}

NTSTATUS ReadFromFile(_In_ HANDLE hFile, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_ ULONG _cb = 0, _In_ ULONG cb_ = 0)
{
	NTSTATUS status;
	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb;

	if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
	{
		if (fsi.EndOfFile.QuadPart > 0x10000000)
		{
			status = STATUS_FILE_TOO_LARGE;
		}
		else
		{
			if (PBYTE pb = (PBYTE)LocalAlloc(LMEM_FIXED, _cb + fsi.EndOfFile.LowPart + cb_))
			{
				if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb + _cb, fsi.EndOfFile.LowPart, 0, 0)))
				{
					LocalFree(pb);
				}
				else
				{
					*ppb = pb;
					*pcb = (ULONG)iosb.Information;
				}
			}
			else
			{
				status = STATUS_NO_MEMORY;
			}
		}
	}

	return status;
}

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_ ULONG _cb/* = 0*/, _In_ ULONG cb_ /*= 0*/)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = '*' == *lpFileName ? ExpandName(lpFileName + 1, &ObjectName) : 
		RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;

		status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, 
			FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			status = ReadFromFile(hFile, ppb, pcb, _cb, cb_);
			NtClose(hFile);
		}
	}

	return status;
}

NTSTATUS Hmac2(_In_ PCWSTR pszAlgId,
			   _In_ PUCHAR pbCV,
			   _In_ ULONG cbCV,
			   _In_ PUCHAR pbInput1, 
			   _In_ ULONG cbInput1, 
			   _In_ PUCHAR pbInput2, 
			   _In_ ULONG cbInput2, 
			   _Out_ PBYTE pbHash, 
			   _In_ ULONG cbHash)
{
	BCRYPT_ALG_HANDLE hAlgorithm;

	NTSTATUS status;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
	{
		BCRYPT_HASH_HANDLE hHash;

		status = BCryptCreateHash(hAlgorithm, &hHash, 0, 0, pbCV, cbCV, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			0 <= (status = BCryptHashData(hHash, pbInput1, cbInput1, 0)) &&
				0 <= (status = BCryptHashData(hHash, pbInput2, cbInput2, 0)) &&
				0 <= (status = BCryptFinishHash(hHash, pbHash, cbHash, 0));

			BCryptDestroyHash(hHash);
		}
	}

	return status;
}

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey,
				   _In_ BCRYPT_ALG_HANDLE hAlgorithm,
				   _In_ PBYTE pbSecret, 
				   _In_ ULONG cbSecret, 
				   _In_ PCWSTR ChainingMode,
				   _In_opt_ ULONG MessageBlockLength/* = 0*/)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, 0, 0, pbSecret, cbSecret, 0)))
	{
		if (0 <= (status = BCryptSetProperty(hKey, BCRYPT_CHAINING_MODE, 
			(PBYTE)ChainingMode, (1 + (ULONG)wcslen(ChainingMode)) * sizeof(WCHAR), 0)) &&
			(!MessageBlockLength || 0 <= (status = BCryptSetProperty(hKey, 
			BCRYPT_MESSAGE_BLOCK_LENGTH, (PBYTE)&MessageBlockLength, sizeof(MessageBlockLength), 0))))
		{
			*phKey = hKey;
			return STATUS_SUCCESS;
		}

		BCryptDestroyKey(hKey);
	}

	return status;
}

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
				   _In_ PBYTE pbSecret, 
				   _In_ ULONG cbSecret, 
				   _In_ PCWSTR ChainingMode,
				   _In_opt_ ULONG MessageBlockLength/* = 0*/)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0)))
	{
		status = GenAesKey(phKey, hAlgorithm, pbSecret, cbSecret, ChainingMode, MessageBlockLength);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS CFBXcrypt(PUCHAR pbSymKey, ULONG cbSymKey, PBYTE pb, ULONG cb, PBYTE pbOut, BOOL bDecrypt)
{
	NTSTATUS status;

	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (status = GenAesKey(&hKey, pbSymKey, cbSymKey, BCRYPT_CHAIN_MODE_CFB, 16)))
	{
		UCHAR b[16] = {};
		ULONG ex = cb & 15, s;
		cb &= ~15;
		if (ex)
		{
			memcpy(b, pb + cb, ex);
		}

		auto BCryptXcrypt = bDecrypt ? BCryptDecrypt : BCryptEncrypt;

		0 <= (status = cb ? BCryptXcrypt(hKey, pb, cb, 0, 0, 0, pbOut, cb, &cb, 0) : 0) &&
			0 <= (status = ex ? BCryptXcrypt(hKey, b, sizeof(b), 0, 0, 0, b, sizeof(b), &s, 0) : 0);

		if (ex)
		{
			memcpy(pbOut + cb, b, ex);
		}

		BCryptDestroyKey(hKey);
	}

	return status;
}

NTSTATUS ImportPublicKey(_Out_ BCRYPT_KEY_HANDLE *phKey, _In_ PCWSTR pszAlgId, _In_ PBYTE pbKey, _In_ ULONG cbKey)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_PUBLIC_KEY_BLOB, phKey, pbKey, cbKey, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phAesKey, _In_ BCRYPT_KEY_HANDLE hPrivKey, _In_ BCRYPT_KEY_HANDLE hPubKey)
{
	HRESULT hr;

	BCRYPT_SECRET_HANDLE hSecret = 0;
	if (0 <= (hr = BCryptSecretAgreement(hPrivKey, hPubKey, &hSecret, 0)))
	{
		BYTE pbSecret[66], pbHash[32];
		ULONG cbSecret, cbHash = sizeof(pbHash);

		hr = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, 0, pbSecret, sizeof(pbSecret), &cbSecret, 0);

		BCryptDestroySecret(hSecret);

		if (0 <= hr && HR(hr, CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, pbSecret, cbSecret, pbHash, &cbHash)))
		{
			hr = GenAesKey(phAesKey, pbHash, cbHash, BCRYPT_CHAIN_MODE_GCM);
		}
	}

	return hr;
}

NTSTATUS GetKeyBlockLength(_In_ BCRYPT_KEY_HANDLE hKey, _Out_ PULONG BlockLength)
{
	ULONG cb;
	return BCryptGetProperty(hKey, BCRYPT_BLOCK_LENGTH, (PBYTE)BlockLength, sizeof(ULONG), &cb, 0);
}

NTSTATUS GetAlgorithmName(_In_ BCRYPT_KEY_HANDLE hKey, _Out_ PWSTR pszAlgId, _In_ ULONG cb)
{
	return BCryptGetProperty(hKey, BCRYPT_ALGORITHM_NAME, (PBYTE)pszAlgId, cb, &cb, 0);
}

NTSTATUS CreateKeyPairKey(_In_ BCRYPT_KEY_HANDLE *phKey, PCWSTR pszAlgId, ULONG dwLength/* = 0*/)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;
		status = BCryptGenerateKeyPair(hAlgorithm, &hKey, dwLength, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			if (0 <= (status = BCryptFinalizeKeyPair(hKey, 0)))
			{
				*phKey = hKey;
				return STATUS_SUCCESS;
			}

			BCryptDestroyKey(hKey);
		}
	}

	return status;
}

HRESULT GetPublicKeyFromCert(_Out_ BCRYPT_KEY_HANDLE* phKey, 
							 _In_ const BYTE *pbCertEncoded, 
							 _In_ DWORD cbCertEncoded, 
							 _In_ ULONG dwFlags)
{
	HRESULT hr;
	if (PCCERT_CONTEXT pCertContext = HR(hr, CertCreateCertificateContext(X509_ASN_ENCODING, pbCertEncoded, cbCertEncoded)))
	{
		HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, 
			&pCertContext->pCertInfo->SubjectPublicKeyInfo, dwFlags, 0, phKey));

		CertFreeCertificateContext(pCertContext);
	}

	return hr;
}

#define BDH(n) BCRYPT_ECDH_P ## n ## _ALGORITHM
#define BDSA(n) BCRYPT_ECDSA_P ## n ## _ALGORITHM

#define FAI(pcszAlgId, bSign, n) if (!wcscmp(pcszAlgId, BDH(n))) return bSign ? BDSA(n) : 0;\
	if (!wcscmp(pcszAlgId, BDSA(n))) return bSign ? 0 : BDH(n);

PCWSTR NewAlgName(_In_ PCWSTR pcszAlgId, _In_ BOOL bSign)
{
	FAI(pcszAlgId, bSign, 256);
	FAI(pcszAlgId, bSign, 384);
	FAI(pcszAlgId, bSign, 521);

	return 0;
}

PCWSTR FixAlgName(_In_ PCWSTR pcszAlgId, _Inout_ PVOID pvBlob, _In_ BOOL bSign)
{
	if (PCWSTR pcszNewAlgId = NewAlgName(pcszAlgId, bSign))
	{
		(reinterpret_cast<BCRYPT_KEY_BLOB*>(pvBlob)->Magic &= 0xFF00FFFF) |= bSign ? ('S' << 16) : ('K' << 16);
		return pcszNewAlgId;
	}

	return pcszAlgId;
}

HRESULT NKeyToBKey(_In_ BOOL bSign, _In_ NCRYPT_KEY_HANDLE hKey, _Out_ BCRYPT_KEY_HANDLE* phKey)
{
	PBYTE pb = 0;
	ULONG cb = 0, s;
	NTSTATUS status;
	while (NOERROR == (status = NCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, 0, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			WCHAR szAlgId[16];
			if (NOERROR == (status = NCryptGetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)szAlgId, sizeof(szAlgId), &s, 0)))
			{
				BCRYPT_ALG_HANDLE hAlgorithm;
				if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, FixAlgName(szAlgId, pb, bSign), 0, 0)))
				{
					status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_PRIVATE_KEY_BLOB, phKey, pb, cb, 0);
					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}
			}

			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return status;
}

HRESULT GetPrivateKeyFromCert(_In_ BOOL bSign, _In_ PCCERT_CONTEXT pCertContext, _Out_ BCRYPT_KEY_HANDLE* phKey)
{
	HRESULT hr;
	ULONG dwKeySpec;
	BOOL CallerFreeProvOrNCryptKey;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey;

	if (HR(hr, CryptAcquireCertificatePrivateKey(pCertContext, 
		CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, 0, &hKey, &dwKeySpec, &CallerFreeProvOrNCryptKey)))
	{
		hr = NKeyToBKey(bSign, hKey, phKey);
		if (CallerFreeProvOrNCryptKey)
		{
			switch (dwKeySpec)
			{
			case CERT_NCRYPT_KEY_SPEC:
				NCryptFreeObject(hKey);
				break;
			default:
				CryptReleaseContext(hKey, 0);
				break;
			}
		}
	}

	return hr;
}

HRESULT NKeyToBKey_PKCS8(_In_ BOOL bSign, _In_ NCRYPT_KEY_HANDLE hKey, _Out_ BCRYPT_KEY_HANDLE* phKey)
{
	HRESULT hr;
	union {
		UCHAR pp[sizeof(CRYPT_PKCS12_PBE_PARAMS)+8];
		CRYPT_PKCS12_PBE_PARAMS params;
	};
	BCryptBuffer buf[] = { 
		{ sizeof(pp), NCRYPTBUFFER_PKCS_ALG_PARAM, pp },
		{
			sizeof(szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES), 
				NCRYPTBUFFER_PKCS_ALG_OID, 
				const_cast<PSTR>(szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES)
		},
	};
	NCryptBufferDesc ParameterList { NCRYPTBUFFER_VERSION, _countof(buf), buf };

	params.iIterations = 1;
	params.cbSalt = sizeof(pp) - sizeof(CRYPT_PKCS12_PBE_PARAMS);

	PBYTE pb = 0;
	ULONG cb = 0;
	while (NOERROR == (hr = NCryptExportKey(hKey, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &ParameterList, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			NCRYPT_PROV_HANDLE hProvider;

			if (NOERROR == (hr = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0)))
			{
				hr = NCryptImportKey(hProvider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, 
					&ParameterList, &hKey, pb, cb, NCRYPT_DO_NOT_FINALIZE_FLAG);

				NCryptFreeObject(hProvider);

				if (NOERROR == hr)
				{
					static const ULONG flags = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

					if (NOERROR == (hr = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&flags, sizeof(flags), 0)) &&
						NOERROR == (hr = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG)))
					{
						hr = NKeyToBKey(bSign, hKey, phKey);
					}

					NCryptFreeObject(hKey);
				}
			}

			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return hr;
}

HRESULT PFXImport(_In_ BOOL bSign, 
				  _In_ PCWSTR lpFileName,
				  _In_ PCWSTR szPassword,
				  _Out_ BCRYPT_KEY_HANDLE* phKey,
				  _Out_opt_ PCCERT_CONTEXT* ppCertContext/* = 0*/,
				  _Out_writes_bytes_opt_(SHA1_DIGEST_SIZE) PBYTE pbHash/* = 0*/)
{
	HRESULT hr;
	CRYPT_DATA_BLOB PFX;
	if (NOERROR == (hr = ReadFromFile(lpFileName, &PFX.pbData, &PFX.cbData)))
	{
		if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(&PFX, szPassword,
			PKCS12_ALWAYS_CNG_KSP | PKCS12_NO_PERSIST_KEY | NCRYPT_ALLOW_EXPORT_FLAG)))
		{
			PCCERT_CONTEXT pCertContext = 0;
			while (pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, pCertContext)))
			{
				CERT_KEY_CONTEXT ckc;
				ULONG cb = sizeof(ckc);
				if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, &ckc, &cb))
				{
					if (CERT_NCRYPT_KEY_SPEC == ckc.dwKeySpec)
					{
						BCRYPT_KEY_HANDLE hKey;

						if (!(hr = NKeyToBKey_PKCS8(bSign, ckc.hNCryptKey, &hKey)))
						{
							*phKey = hKey;
							
							if (pbHash)
							{
								ULONG cbHash = SHA1_DIGEST_SIZE;
								if (!HR(hr, CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, 0, 
									pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, pbHash, &cbHash)))
								{
									*phKey = 0;
									BCryptDestroyKey(hKey);
									ppCertContext = 0;
								}
							}

							if (ppCertContext)
							{
								if (!(*ppCertContext = HR(hr, CertCreateCertificateContext(X509_ASN_ENCODING,
									pCertContext->pbCertEncoded, pCertContext->cbCertEncoded))))
								{
									*phKey = 0;
									BCryptDestroyKey(hKey);
								}
							}
						}

						CertFreeCertificateContext(pCertContext);
						break;
					}
				}
			}

			CertCloseStore(hStore, 0);
		}

		LocalFree(PFX.pbData);
	}

	return hr;
}

BOOL IsSupportedAlg(_In_ PCRYPT_ALGORITHM_IDENTIFIER Algorithm, _Out_ PCWSTR *ppszEccAlgId)
{
	*ppszEccAlgId = 0;

	if (!strcmp(szOID_RSA_RSA, Algorithm->pszObjId))
	{
		return TRUE;
	}

	if (!strcmp(szOID_ECC_PUBLIC_KEY, Algorithm->pszObjId))
	{
		union {
			UCHAR buf[0x40];
			PCSTR AlgorithmParameter;
		};

		ULONG cb = sizeof(buf);

		if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER, 
			Algorithm->Parameters.pbData, Algorithm->Parameters.cbData, 0, 0, buf, &cb))
		{
			if (!strcmp(AlgorithmParameter, szOID_ECC_CURVE_P256))
			{
				*ppszEccAlgId = BCRYPT_ECDH_P256_ALGORITHM;
				return TRUE;
			}
			
			if (!strcmp(AlgorithmParameter, szOID_ECC_CURVE_P384))
			{
				*ppszEccAlgId = BCRYPT_ECDH_P384_ALGORITHM;
				return TRUE;
			}
			
			if (!strcmp(AlgorithmParameter, szOID_ECC_CURVE_P521))
			{
				*ppszEccAlgId = BCRYPT_ECDH_P521_ALGORITHM;
				return TRUE;
			}
		}
	}

	return FALSE;
}

NTSTATUS TransformEccKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
						 _In_ BCRYPT_KEY_HANDLE hKey, 
						 _In_ PCWSTR pszAlgId,
						 _In_ PCWSTR pszBlobType)
{
	PBYTE pb = 0;
	ULONG cb = 0;
	NTSTATUS status;
	while (0 <= (status = BCryptExportKey(hKey, 0, pszBlobType, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			BCRYPT_ALG_HANDLE hAlgorithm;

			if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
			{
				reinterpret_cast<BCRYPT_KEY_BLOB*>(pb)->Magic ^= ('S' ^ 'K') << 16;
				status = BCryptImportKeyPair(hAlgorithm, 0, pszBlobType, phKey, pb, cb, 0);
				BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			}

			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return status;
}

NTSTATUS BKeyToNkey(_In_ BOOL bSign,
					_In_ BCRYPT_KEY_HANDLE hKey, 
					_In_ PCWSTR pszKeyName, 
					_In_opt_ ULONG dwFlags/* = 0*/, 
					_In_opt_ ULONG ExportFlags/* = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG*/)
{
	PBYTE pb = 0;
	ULONG cb = 0;
	NTSTATUS status;
	while (0 <= (status = BCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			if ('CE' == (WORD)reinterpret_cast<BCRYPT_KEY_BLOB*>(pb)->Magic)
			{
				(reinterpret_cast<BCRYPT_KEY_BLOB*>(pb)->Magic &= 0xFF00FFFF) |= bSign ? ('S' << 16) : ('K' << 16);
			}

			NCRYPT_PROV_HANDLE hProvider;
			if (!NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0))
			{
				NCryptBuffer buf = { 
					(1 + (ULONG)wcslen(pszKeyName)) * sizeof(WCHAR), NCRYPTBUFFER_PKCS_KEY_NAME, const_cast<PWSTR>(pszKeyName) 
				};
				NCryptBufferDesc ParameterList = { NCRYPTBUFFER_VERSION, 1, &buf };
				NCRYPT_KEY_HANDLE hNKey;
				if (NOERROR == (status = NCryptImportKey(hProvider, 0, BCRYPT_PRIVATE_KEY_BLOB, &ParameterList, 
					&hNKey, pb, cb, ExportFlags ? NCRYPT_DO_NOT_FINALIZE_FLAG | dwFlags : dwFlags & ~NCRYPT_DO_NOT_FINALIZE_FLAG)))
				{
					if (ExportFlags)
					{
						if (NOERROR == (status = NCryptSetProperty(hNKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&ExportFlags, sizeof(ExportFlags), 0)))
						{
							status = NCryptFinalizeKey(hNKey, 0);
						}
					}
					NCryptFreeObject(hNKey);
				}
				NCryptFreeObject(hProvider);
			}
			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return status;
}

_NT_END