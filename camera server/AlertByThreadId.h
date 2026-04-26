#pragma once

union TIDFA {
	LONG m_dwThreadId;
	struct {
		ULONG m_wait : 1;
		ULONG m_alert : 1;
	};

	TIDFA(ULONG dwThreadId = GetCurrentThreadId()) : m_dwThreadId(dwThreadId)
	{
	}

	void Alert();

	NTSTATUS WaitForAlert(_In_opt_ PLARGE_INTEGER Timeout = 0);
};
