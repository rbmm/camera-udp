#pragma once

HRESULT GetLastHresult(ULONG dwError = GetLastError());

inline HRESULT GetLastHresult(BOOL fOk)
{
	return fOk ? S_OK : GetLastHresult();
}

template <typename T> T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastHresult(GetLastError());
	return t;
}

class CLogFile
{
	HANDLE _hRoot = 0;
	HANDLE _hFile = 0;
	SRWLOCK _SRWLock = SRWLOCK_INIT;
	ULONG _day = 0;

	NTSTATUS Init(ULONG wDay);
public:
	static CLogFile _S_LF;

	~CLogFile();

	static ULONG GetDay()
	{
		SYSTEMTIME tf;
		GetLocalTime(&tf);
		return tf.wDay;
	}

	void write(const void* buf, ULONG cb, ULONG wDay = GetDay());

	NTSTATUS Init();

	void printf(_In_ PCWSTR format, ...);

	HRESULT PrintError(PCSTR prefix, HRESULT dwError = GetLastHresult());
};

#define DbgPrint(fmt, ...) CLogFile::_S_LF.printf(_CRT_WIDE(fmt), __VA_ARGS__ )

#define logError(...) CLogFile::_S_LF.PrintError( __VA_ARGS__ )

#define LOG(args)  CLogFile::_S_LF.args

#pragma message("!!! LOG >>>>>>")
