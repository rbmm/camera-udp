#include "stdafx.h"

_NT_BEGIN

#include "log.h"
#include "../inc/initterm.h"
#include "SvcBase.h"

BOOL StartServer();

#include "AlertByThreadId.h"

class CSvc : public CSvcBase
{
	TIDFA m_tid;

	virtual HRESULT Run()
	{
		DbgPrint("+++ Run\r\n");

		do
		{
			ULONG dwState = m_dwTargetState;

			DbgPrint("state:= %x\r\n", dwState);

			SetState(dwState, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE);

			if (SERVICE_RUNNING == dwState)
			{
				WSADATA wd;
				if (!WSAStartup(WINSOCK_VERSION, &wd))
				{
					if (0 <= MFStartup(MF_VERSION))
					{
						if (StartServer())
						{
							DbgPrint("Start Server\r\n");
							m_tid.WaitForAlert();
							DbgPrint("alert\r\n");
						}
						else
						{
							m_dwTargetState = SERVICE_STOPPED;
						}

						MFShutdown();
					}

					WSACleanup();
				}
			}
			else
			{
				m_tid.WaitForAlert();
			}

		} while (SERVICE_STOPPED != m_dwTargetState);

		DbgPrint("--- Run\r\n");

		return S_OK;
	}

	virtual ULONG Handler(
		ULONG    dwControl,
		ULONG    /*dwEventType*/,
		PVOID   /*lpEventData*/
		)
	{
		switch (dwControl)
		{
		case SERVICE_CONTROL_CONTINUE:
		case SERVICE_CONTROL_PAUSE:
		case SERVICE_CONTROL_STOP:
			return m_tid.Alert(), NOERROR;
		}

		return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
	}
};

void NTAPI ServiceMain(DWORD argc, PWSTR argv[])
{
	if (argc)
	{
		CSvc o;
		o.ServiceMain(argv[0]);
	}
}

HRESULT UnInstallService();
HRESULT InstallService();

EXTERN_C
NTSYSAPI 
VOID 
NTAPI 
RtlSetLastWin32ErrorAndNtStatusFromNtStatus( _In_ NTSTATUS Status );

void CALLBACK ep(void*)
{
	initterm();
	LOG(Init());

	PWSTR cmd = GetCommandLineW();
	if (wcschr(cmd, '\n'))
	{
		const static SERVICE_TABLE_ENTRY ste[] = { 
			{ const_cast<PWSTR>(L"RBMMCAMERA"), ServiceMain }, {} 
		};

		if (!StartServiceCtrlDispatcher(ste))
		{
			logError("SERVICE_CONTROL_STOP");
		}

		DbgPrint("Service Exit\r\n");
	}
	else if (cmd = wcschr(cmd, '*'))
	{
		switch (cmd[1])
		{
		case 'i': // *i*crc2*crc1*
			logError("install", InstallService());
			break;
		case 'u':
			logError("uninstall", UnInstallService());
			break;
		default:
			__ip:
			logError("cmd line", STATUS_INVALID_PARAMETER);
			break;
		}
	}
	else
	{
		goto __ip;
	}

	destroyterm();
	ExitProcess(0);
}

_NT_END