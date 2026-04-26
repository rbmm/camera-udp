#include "stdafx.h"

_NT_BEGIN

#include "AlertByThreadId.h"

void TIDFA::Alert()
{
	union {
		ULONG dwThreadId;
		struct {
			ULONG wait : 1;
			ULONG alert : 1;
		};
	};
	union {
		ULONG _dwThreadId;
		struct {
			ULONG _wait : 1;
			ULONG _alert : 1;
		};
	};

	dwThreadId = m_dwThreadId;

	for (;;)
	{
		_dwThreadId = dwThreadId;

		alert = 1, wait = 0;

		if (_dwThreadId == (dwThreadId = InterlockedCompareExchange(&m_dwThreadId, dwThreadId, _dwThreadId)))//--0
		{
			if (wait && !alert)
			{
				wait = 0;
				if (0 > ZwAlertThreadByThreadId((HANDLE)(ULONG_PTR)dwThreadId))
				{
					__debugbreak();
				}
			}

			break;
		}
	}
}

NTSTATUS TIDFA::WaitForAlert(_In_opt_ PLARGE_INTEGER Timeout/* = 0*/)
{
	union {
		ULONG dwThreadId;
		struct {
			ULONG wait : 1;
			ULONG alert : 1;
		};
	};
	union {
		ULONG _dwThreadId;
		struct {
			ULONG _wait : 1;
			ULONG _alert : 1;
		};
	};

	dwThreadId = m_dwThreadId;

	for (;;)
	{
		_dwThreadId = dwThreadId;

		if (wait)
		{
			__debugbreak();
		}

		if (alert)
		{
			alert = 0;
			wait = 0;
		}
		else
		{
			wait = 1;
		}

		BOOL bNeedWait = wait;

		if (_dwThreadId == (dwThreadId = InterlockedCompareExchange(&m_dwThreadId, dwThreadId, _dwThreadId)))//--1
		{
			if (bNeedWait)
			{
				NTSTATUS status = ZwWaitForAlertByThreadId(this, Timeout);

				dwThreadId = m_dwThreadId;

				for (;;)
				{
					_dwThreadId = dwThreadId;

					wait = 0, alert = 0;

					if (_dwThreadId == (dwThreadId = InterlockedCompareExchange(&m_dwThreadId, dwThreadId, _dwThreadId)))//--2
					{
						if (alert)
						{
							if (STATUS_ALERTED != status)
							{
								LARGE_INTEGER zt = {};

								ULONG spinCount = 0;
								while (STATUS_ALERTED != ZwWaitForAlertByThreadId(this, &zt))
								{
									switch (++spinCount >> 3)
									{
									case 0: YieldProcessor();
										continue;
									case 1: SwitchToThread();
										continue;
									}

									Sleep(1);
								}

								return STATUS_ALERTED;
							}
						}

						return status;
					}
				}
			}

			return STATUS_ALERTED;
		}
	}
}

_NT_END