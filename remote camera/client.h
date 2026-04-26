#pragma once

NTSTATUS GetKeyCrc(BCRYPT_KEY_HANDLE hKey, PULONGLONG pcrc);

#include "video.h"
#include "H264.h"
#include "TUDP.h"

class CClient : public Endpoint, public H264
{
	LONGLONG _crc = 0, _cbData;
	BCRYPT_KEY_HANDLE _hKey = 0;
	HWND _hwnd, _hwndDlg;
	VBmp* _vid = 0;
	ULONG _biCompression, _biWidth, _biHeight;

	virtual NTSTATUS Accept(PSOCKADDR_INET /*psi*/);

	virtual NTSTATUS OnConnect();

	virtual void OnDisconnect();

	virtual NTSTATUS OnUserData(ULONG type, PBYTE pb, ULONG cb);

	virtual BCRYPT_KEY_HANDLE GetPrivateKey()
	{
		return _hKey;
	}

	virtual ~CClient();

public:

	ULONG GetFormats()
	{
		return SendUserData('init');
	}

	BOOL Stop()
	{
		return !SendUserData('stop');
	}

	void test()
	{
		SendUserData('test');
	}

	LONGLONG getDataSize()
	{
		return _cbData;
	}

	BOOL Start(VBmp* vid, ULONG biCompression, ULONG i, ULONG j);

	void OnStop()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		SendUserData('stop');
	}

	CClient(CClientServerR* parent, HWND hwndDlg, HWND hwnd) : Endpoint(parent), _hwnd(hwnd), _hwndDlg(hwndDlg)
	{
	}

	void DestroyKey()
	{
		if (_hKey) BCryptDestroyKey(_hKey), _hKey = 0;
	}

	void SetPrivateKey(BCRYPT_KEY_HANDLE hKey)
	{
		if (_hKey)
		{
			__debugbreak();
		}
		_hKey = hKey;
	}
};

BOOL CreateClient(CClient** ppcln, HWND hwndDlg, HWND hwnd);