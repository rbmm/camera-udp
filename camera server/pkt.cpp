#include "stdafx.h"

_NT_BEGIN

#include "util.h"
#include "pkt.h"

HRESULT UH_PACKET::AES_Decode_I(_In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pbData, _In_ ULONG cbData)
{
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi = { 
		sizeof(acmi), BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, Nonce, sizeof(Nonce), 0, 0, Tag, sizeof(Tag)
	};

	return BCryptDecrypt(hKey, pbData, cbData, &acmi, 0, 0, pbData, cbData, &cbData, 0);
}

HRESULT UH_PACKET::AES_Encode_I(_In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pbData, _In_ ULONG cbData, _In_ PBYTE pb)
{
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi = { 
		sizeof(acmi), BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, Nonce, sizeof(Nonce), 0, 0, Tag, sizeof(Tag)
	};

	HRESULT hr;
	if (0 <= (hr = BCryptGenRandom(0, Nonce, sizeof(Nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		hr = BCryptEncrypt(hKey, pbData, cbData, &acmi, 0, 0, pb, cbData, &cbData, 0);
	}

	return hr;
}

HRESULT UH_PACKET::RSA_Encode(_In_ BCRYPT_KEY_HANDLE hPubKey, 
							  _In_ PBYTE pbData, 
							  _In_ ULONG cbData, 
							  _In_ ULONG BlockLength,
							  _Reserved_ BCRYPT_KEY_HANDLE*/* = 0*/)
{
	if (pbData)
	{
		magic = e_rsa;
		memcpy(rsa_data, pbData, cbData);
	}

	DataSize = _byteswap_ulong(cbData);

	return BCryptEncrypt(hPubKey, encrypted, BlockLength, 0, 0, 0, encrypted, BlockLength, &BlockLength, BCRYPT_PAD_NONE);
}

HRESULT UH_PACKET::RSA_AES_Encode(_In_ BCRYPT_KEY_HANDLE hPubKey, 
								  _In_opt_ PBYTE pbData, 
								  _In_opt_ ULONG cbData, 
								  _In_ ULONG BlockLength,
								  _Out_opt_ BCRYPT_KEY_HANDLE* phKey/* = 0*/)
{
	BCRYPT_KEY_HANDLE hKey;

	HRESULT hr;
	if (0 <= (hr = BCryptGenRandom(0, aes, sizeof(aes), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) &&
		0 <= (hr = GenAesKey(&hKey, aes, sizeof(aes), BCRYPT_CHAIN_MODE_GCM)))
	{
		if (0 <= (hr = cbData ? AES_Encode_I(hKey, pbData, cbData, rsa_aes_data) : NOERROR))
		{
			magic = e_rsa_aes;
			hr = RSA_Encode(hPubKey, 0, cbData, BlockLength);
		}

		if (NOERROR == hr && phKey)
		{
			*phKey = hKey;
		}
		else
		{
			BCryptDestroyKey(hKey);
		}
	}

	return hr;
}

NTSTATUS ImportPubKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pb, _In_ ULONG cb)
{
	WCHAR pszAlgId[32];
	NTSTATUS status;

	ULONG cbResult;
	if (0 <= (status = BCryptGetProperty(hKey, BCRYPT_ALGORITHM_NAME, (PBYTE)pszAlgId, sizeof(pszAlgId), &cbResult, 0)))
	{
		BCRYPT_ALG_HANDLE hAlgorithm;
		if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
		{
			status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_PUBLIC_KEY_BLOB, phKey, pb, cb, 0);
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		}
	}
	return status;
}

HRESULT UH_PACKET::DH_Decode(_In_ BCRYPT_KEY_HANDLE hPrivKey, 
							 _In_ ULONG cbPacket, 
							 _Out_ PBYTE* ppbData, 
							 _Out_ ULONG* pcbData,
							 _Out_opt_ BCRYPT_KEY_HANDLE* phKey/* = 0*/)
{
	if (DataSize < (cbPacket -= offsetof(UH_PACKET, buf)))
	{
		HRESULT hr;
		BCRYPT_KEY_HANDLE hPubKey, hAesKey;

		if (0 <= (hr = ImportPubKey(&hPubKey, hPrivKey, buf, cbPacket -= DataSize)))
		{
			hr = GenAesKey(&hAesKey, hPrivKey, hPubKey);

			BCryptDestroyKey(hPubKey);

			if (NOERROR == hr)
			{
				PBYTE pb = buf + cbPacket;

				if (!(cbPacket = DataSize) || 0 <= (hr = AES_Decode_I(hAesKey, pb, cbPacket)))
				{
					*ppbData = pb, *pcbData = cbPacket;
				}

				if (!hr && phKey)
				{
					*phKey = hAesKey;
				}
				else
				{
					BCryptDestroyKey(hAesKey);
				}
			}
		}

		return hr;
	}

	return STATUS_BAD_DATA;
}

HRESULT UH_PACKET::RSA_Decode(_In_ BCRYPT_KEY_HANDLE hPrivKey, 
							  _In_ ULONG cbPacket, 
							  _Out_ PBYTE* ppbData, 
							  _Out_ ULONG* pcbData,
							  _Reserved_ BCRYPT_KEY_HANDLE*/* = 0*/)
{
	ULONG BlockLength;
	HRESULT hr;
	if (0 <= (hr = GetKeyBlockLength(hPrivKey, &BlockLength)))
	{
		if (offsetof(UH_PACKET, encrypted) + BlockLength > cbPacket)
		{
			return STATUS_BAD_DATA;
		}

		if (0 <= (hr = BCryptDecrypt(hPrivKey, encrypted, BlockLength, 0, 0, 0,
			encrypted, BlockLength, &BlockLength, BCRYPT_PAD_NONE)))
		{
			*ppbData = rsa_data, *pcbData = _byteswap_ulong(DataSize);
		}
	}

	return hr;
}

HRESULT UH_PACKET::RSA_AES_Decode(_In_ BCRYPT_KEY_HANDLE hKey, 
								  _In_ ULONG cbPacket, 
								  _Out_ PBYTE* ppbData, 
								  _Out_ ULONG* pcbData,
								  _Out_opt_ BCRYPT_KEY_HANDLE* phKey/* = 0*/)
{
	PBYTE pb;
	ULONG cb;
	HRESULT hr;
	if (0 <= (hr = RSA_Decode(hKey, cbPacket, &pb, &cb)))
	{
		if (offsetof(UH_PACKET, rsa_aes_data) + cb > cbPacket)
		{
			return STATUS_BAD_DATA;
		}

		if (0 <= (hr = GenAesKey(&hKey, aes, sizeof(aes), BCRYPT_CHAIN_MODE_GCM)))
		{
			if (!(hr = AES_Decode_I(hKey, rsa_aes_data, cb)) && phKey)
			{
				*phKey = hKey;
			}
			else
			{
				BCryptDestroyKey(hKey);
			}
			*ppbData = rsa_aes_data, *pcbData = cb;
		}
	}

	return hr;
}

HRESULT UH_PACKET::AES_Decode(_In_ BCRYPT_KEY_HANDLE hKey, 
							  _Out_ PBYTE* ppbData, 
							  _Out_ ULONG* pcbData)
{
	ULONG cb = PacketSize;
	if (offsetof(UH_PACKET, buf) < cb)
	{
		if (UH_PACKET::e_aes == magic && (cb -= offsetof(UH_PACKET, buf)) == DataSize)
		{
			*ppbData = buf, *pcbData = cb;
			return AES_Decode_I(hKey, buf, cb);
		}
	}

	return STATUS_BAD_DATA;
}

HRESULT UH_PACKET::Decode(_In_ BCRYPT_KEY_HANDLE hPrivKey, 
						  _Out_ PBYTE* ppbData, 
						  _Out_ ULONG* pcbData,
						  _Out_opt_ BCRYPT_KEY_HANDLE* phKey/* = 0*/)
{
	if (phKey) *phKey = 0;

	HRESULT (UH_PACKET::* pfx)(BCRYPT_KEY_HANDLE , ULONG , PBYTE* , ULONG* , BCRYPT_KEY_HANDLE* );

	switch (magic)
	{
	case e_rsa:
		pfx = &UH_PACKET::RSA_Decode;
		break;
	case e_rsa_aes:
		pfx = &UH_PACKET::RSA_AES_Decode;
		break;
	case e_ecdh:
		pfx = &UH_PACKET::DH_Decode;
		break;
	default: return STATUS_BAD_DATA;
	}

	return (this->*pfx)(hPrivKey, PacketSize, ppbData, pcbData, phKey);
}

HRESULT UH_PACKET::RSA_Encode(_In_ BCRYPT_KEY_HANDLE hPubKey, 
							  _In_opt_ PBYTE pbData, 
							  _In_opt_ ULONG cbData, 
							  _Out_ CDataPacket** ppacket,
							  _Out_opt_ BCRYPT_KEY_HANDLE* phKey/* = 0*/)
{
	HRESULT hr;
	ULONG BlockLength;

	if (0 <= (hr = GetKeyBlockLength(hPubKey, &BlockLength)))
	{
		ULONG PacketSize, MinPacketSize = offsetof(UH_PACKET, encrypted) + BlockLength;
		HRESULT (UH_PACKET::* pf)(BCRYPT_KEY_HANDLE , PBYTE , ULONG , ULONG, BCRYPT_KEY_HANDLE* );

		if (phKey || BlockLength - sizeof(ULONG) < cbData)
		{
			pf = &UH_PACKET::RSA_AES_Encode;
			if ((PacketSize = offsetof(UH_PACKET, rsa_aes_data) + cbData) < MinPacketSize)
			{
				PacketSize = MinPacketSize;
			}
		}
		else
		{
			PacketSize = MinPacketSize;
			pf = &UH_PACKET::RSA_Encode;
		}

		if (CDataPacket* packet = new(PacketSize) CDataPacket)
		{
			UH_PACKET* ph = UH_PACKET::get(packet);

			if (0 <= (hr = (ph->*pf)(hPubKey, pbData, cbData, BlockLength, phKey)))
			{
				ph->PacketSize = PacketSize;
				packet->setDataSize(PacketSize);
				*ppacket = packet;
				return S_OK;
			}

			packet->Release();
		}

		return STATUS_NO_MEMORY;
	}

	return hr;
}

HRESULT UH_PACKET::DH_Encode(_In_ BCRYPT_KEY_HANDLE hPubKey,
							 _In_ PCWSTR pszEccAlgId,
							 _In_opt_ PBYTE pbData, 
							 _In_opt_ ULONG cbData, 
							 _Out_ CDataPacket** ppacket,
							 _Out_opt_ BCRYPT_KEY_HANDLE *phKey/* = 0*/)
{
	BCRYPT_KEY_HANDLE hAesKey, hPrivKey;

	HRESULT hr;
	if (0 <= (hr = CreateKeyPairKey(&hPrivKey, pszEccAlgId)))
	{
		PBYTE pbKey = 0;
		ULONG cbKey = 0;
		ULONG PacketSize = 0;
		UH_PACKET* ph = 0;
		CDataPacket* packet = 0;

		while (0 <= (hr = BCryptExportKey(hPrivKey, 0, BCRYPT_ECCPUBLIC_BLOB, pbKey, cbKey, &cbKey, 0)))
		{
			if (pbKey)
			{
				if (0 <= (hr = GenAesKey(&hAesKey, hPrivKey, hPubKey)))
				{
					if (!cbData || 0 <= (hr = ph->AES_Encode_I(hAesKey, pbData, cbData, ph->buf + cbKey)))
					{
						ph->magic = UH_PACKET::e_ecdh;
						ph->DataSize = cbData;
						ph->PacketSize = PacketSize;
						packet->setDataSize(PacketSize);
						*ppacket = packet;
						packet = 0;
					}

					if (phKey)
					{
						*phKey = hAesKey;
					}
					else
					{
						BCryptDestroyKey(hAesKey);
					}
				}
				break;
			}

			if (packet = new(PacketSize = offsetof(UH_PACKET, buf) + cbKey + cbData) CDataPacket)
			{
				ph = UH_PACKET::get(packet);
				pbKey = ph->buf;
			}
			else
			{
				hr = STATUS_NO_MEMORY;
				break;
			}
		}

		if (packet)
		{
			packet->Release();
		}

		BCryptDestroyKey(hPrivKey);
	}

	return hr;
}

HRESULT UH_PACKET::AES_Encode(_In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pbData, _In_ ULONG cbData)
{
	magic = e_aes, DataSize = cbData, PacketSize = offsetof(UH_PACKET, buf) + cbData;
	return AES_Encode_I(hKey, pbData, cbData, buf);
}

UH_PACKET* UH_PACKET::AES_Allocate(_In_ ULONG cbData, _Out_ PBYTE *ppb, _Out_ CDataPacket** ppacket)
{
	if (CDataPacket* packet = new(offsetof(UH_PACKET, buf) + cbData) CDataPacket)
	{
		UH_PACKET* ph = UH_PACKET::get(packet);
		*ppacket = packet, *ppb = ph->buf;
		packet->setDataSize(offsetof(UH_PACKET, buf) + cbData);
		return ph;
	}

	return 0;
}

HRESULT UH_PACKET::AES_Encode(_In_ BCRYPT_KEY_HANDLE hKey, 
							  _In_ PBYTE pbData, 
							  _In_ ULONG cbData, 
							  _Out_ CDataPacket** ppacket)
{
	PBYTE pb;
	CDataPacket* packet;
	if (UH_PACKET* ph = AES_Allocate(cbData, &pb, &packet))
	{
		HRESULT hr = ph->AES_Encode(hKey, pbData, cbData);
		if (0 <= hr)
		{
			*ppacket = packet;
			return NOERROR;
		}
		packet->Release();

		return hr;
	}

	return STATUS_NO_MEMORY;
}

UH_PACKET* UH_PACKET::Plain_Create(
	_In_opt_ PBYTE pbData, 
	_In_ ULONG cbData, 
	_Out_ CDataPacket** ppacket, 
	_Out_opt_ PBYTE* ppb/* = 0*/)
{
	if (CDataPacket* packet = new(offsetof(UH_PACKET, encrypted) + cbData) CDataPacket)
	{
		*ppacket = packet;
		UH_PACKET* ph = UH_PACKET::get(packet);
		ph->magic = e_plain;
		packet->setDataSize(ph->PacketSize = offsetof(UH_PACKET, encrypted) + cbData);
		if (pbData) memcpy(ph->encrypted, pbData, cbData);
		if (ppb) *ppb = ph->encrypted;
		return ph;
	}

	return 0;
}

HRESULT UH_PACKET::Encode(
						  _In_ BCRYPT_KEY_HANDLE hPubKey, 
						  _In_opt_ PBYTE pbData, 
						  _In_opt_ ULONG cbData, 
						  _Out_ CDataPacket** ppacket,
						  _Out_opt_ BCRYPT_KEY_HANDLE *phKey/* = 0*/)
{
	NTSTATUS status;
	WCHAR szAlgId[16];
	if (0 <= (status = GetAlgorithmName(hPubKey, szAlgId, sizeof(szAlgId))))
	{
		return wcscmp(BCRYPT_RSA_ALGORITHM, szAlgId) 
			? UH_PACKET::DH_Encode(hPubKey, szAlgId, pbData, cbData, ppacket, phKey)
			: UH_PACKET::RSA_Encode(hPubKey, pbData, cbData, ppacket, phKey);
	}

	return status;
}

_NT_END