#pragma once

#include "../asio/packet.h"

class UH_PACKET 
{
public:
	ULONG64 cookie;
private:
	enum PT { e_ecdh = 'HDCE', e_rsa = '*ASR', e_rsa_aes = '+ASR', e_aes = '*SEA', e_plain = 'NALP' } magic;
	ULONG PacketSize;
	union {
		BYTE encrypted[];
		struct {
			ULONG DataSize; // in big endian in case e_rsa !!
			union {
				UCHAR rsa_data[];
				struct {
					UCHAR Nonce[12];
					UCHAR Tag[16];
					union {
						UCHAR buf[]; // ecdh+aes, aes
						struct {
							UCHAR aes[32];
							UCHAR rsa_aes_data[];
						};
					};
				};
			};
		};
	};

	HRESULT AES_Decode_I(_In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pbData, _In_ ULONG cbData);
	
	HRESULT AES_Encode_I(_In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pbData, _In_ ULONG cbData, _In_ PBYTE pb);

	HRESULT RSA_Decode(
		_In_ BCRYPT_KEY_HANDLE hPrivKey, 
		_In_ ULONG cbPacket, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData,
		_Reserved_ BCRYPT_KEY_HANDLE* = 0);
	
	HRESULT RSA_AES_Decode(
		_In_ BCRYPT_KEY_HANDLE hPrivKey, 
		_In_ ULONG cbPacket, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData,
		_Out_opt_ BCRYPT_KEY_HANDLE* phKey = 0);
	
	HRESULT DH_Decode(
		_In_ BCRYPT_KEY_HANDLE hPrivKey, 
		_In_ ULONG cbPacket, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData,
		_Out_opt_ BCRYPT_KEY_HANDLE* phKey = 0);

	HRESULT RSA_Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey, 
		_In_ PBYTE pbData, 
		_In_ ULONG cbData, 
		_In_ ULONG BlockLength,
		_Reserved_ BCRYPT_KEY_HANDLE* = 0);
	
	HRESULT RSA_AES_Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey, 
		_In_opt_ PBYTE pbData, 
		_In_opt_ ULONG cbData, 
		_In_ ULONG BlockLength,
		_Out_opt_ BCRYPT_KEY_HANDLE* phKey = 0);

public:
	//++ Decode

	HRESULT AES_Decode(
		_In_ BCRYPT_KEY_HANDLE hKey, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData);

	HRESULT Decode(
		_In_ BCRYPT_KEY_HANDLE hPrivKey, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData,
		_Out_opt_ BCRYPT_KEY_HANDLE* phKey = 0);

	//-- Decode

	//++ Encode

	HRESULT AES_Encode(_In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pbData, _In_ ULONG cbData);

	static HRESULT AES_Encode(
		_In_ BCRYPT_KEY_HANDLE hKey, 
		_In_ PBYTE pbData, 
		_In_ ULONG cbData, 
		_Out_ CDataPacket** ppacket);

	static HRESULT RSA_Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey, 
		_In_opt_ PBYTE pbData, 
		_In_opt_ ULONG cbData, 
		_Out_ CDataPacket** ppacket,
		_Out_opt_ BCRYPT_KEY_HANDLE *phKey = 0);

	static HRESULT DH_Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey,
		_In_ PCWSTR pszEccAlgId,
		_In_opt_ PBYTE pbData, 
		_In_opt_ ULONG cbData, 
		_Out_ CDataPacket** ppacket,
		_Out_opt_ BCRYPT_KEY_HANDLE *phKey = 0);

	// internal call RSA_Encode or DH_Encode, based on hPubKey type
	static HRESULT Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey, 
		_In_opt_ PBYTE pbData, 
		_In_opt_ ULONG cbData, 
		_Out_ CDataPacket** ppacket,
		_Out_opt_ BCRYPT_KEY_HANDLE *phKey = 0);

	static UH_PACKET* AES_Allocate(_In_ ULONG cbData, _Out_ PBYTE *ppb, _Out_ CDataPacket** ppacket);
	
	static UH_PACKET* Plain_Create(
		_In_opt_ PBYTE pbData, 
		_In_ ULONG cbData, 
		_Out_ CDataPacket** ppacket,
		_Out_opt_ PBYTE* ppb = 0);

	//-- Encode

	static UH_PACKET* get(CDataPacket* packet)
	{
		return (UH_PACKET*)packet->getData();
	}

	ULONG getPacketSize()
	{
		return PacketSize;
	}

	void setPacketSize(ULONG cbPacket)
	{
		PacketSize = cbPacket;
	}

	BOOL IsSizeValid(_In_ ULONG cb)
	{
		return offsetof(UH_PACKET, encrypted) < cb && PacketSize == cb;
	}

	ULONG setPlainSize(ULONG cb)
	{
		return PacketSize = offsetof(UH_PACKET, encrypted) + cb;
	}

	BOOL IsPlainData(_Out_ ULONG *pcb, _Out_ PBYTE* ppb)
	{
		if (e_plain == magic)
		{
			*pcb = PacketSize - offsetof(UH_PACKET, encrypted), *ppb = encrypted;
			return TRUE;
		}
		return FALSE;
	}
};

inline HRESULT CreateSessionKey(
	_In_ BCRYPT_KEY_HANDLE hPubKey,
	_Out_ CDataPacket** ppacket,
	_Out_ BCRYPT_KEY_HANDLE* phKey)
{
	return UH_PACKET::Encode(hPubKey, 0, 0, ppacket, phKey);
}
