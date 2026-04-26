#include "stdafx.h"

_NT_BEGIN
#include "log.h"
#include "util.h"
#include "pkt.h"
#include "TUDP.h"

bool operator==(const SOCKADDR_INET& psi1, const SOCKADDR_INET& psi2)
{
	if (psi1.si_family == psi2.si_family)
	{
		switch (psi1.si_family)
		{
		case AF_INET:
			return !memcmp(&psi1.Ipv4, &psi2.Ipv4, sizeof(SOCKADDR_IN));
		case AF_INET6:
			return !memcmp(&psi1.Ipv6, &psi2.Ipv6, sizeof(SOCKADDR_IN6));
		}
	}
	return false;
}

void PrintIP(PSOCKADDR_INET from, ULONG cb)
{
	CHAR sz[64];
	ULONG cch = _countof(sz);
	NTSTATUS status = -1;

	switch (from->si_family)
	{
	case AF_INET:
		status = RtlIpv4AddressToStringExA(&from->Ipv4.sin_addr, from->Ipv4.sin_port, sz, &cch);
		break;
	case AF_INET6:
		status = RtlIpv6AddressToStringExA(&from->Ipv6.sin6_addr, 
			from->Ipv6.sin6_scope_id ,from->Ipv6.sin6_port, sz, &cch);
		break;
	}

	if (0 <= status)
	{
		DbgPrint("%u bytes from %hs\r\n", cb, sz);
	}
}

struct C_PACKET
{
	ULONG64 client_cookie;
	UCHAR data[];
};

struct P_PACKET
{
	enum : ULONG64 { e_magic = 'GNIP' + 'GNIP' * 0x100000000ULL } magic;
	ULONG64 crc;
};

struct E_PACKET 
{
	ULONG MsgLength;
	ULONG type;
	USHORT M;
	USHORT N;
	UCHAR Buf[];
};

//////////////////////////////////////////////////////////////////////////
// Endpoint

Endpoint::~Endpoint()
{
	if (m_hKey) BCryptDestroyKey(m_hKey);
	if (m_msgb) delete [] m_msgb;
	m_parent->Release();
	DbgPrint("%hs<%p>(%hs)\r\n", __FUNCTION__, this, m_parent->m_name);
}

Endpoint::Endpoint(CClientServerR* parent) : m_parent(parent)
{
	DbgPrint("%hs<%p>(%hs)\r\n", __FUNCTION__, this, parent->m_name);
	parent->AddRef();
	BCryptGenRandom(0, (PBYTE)&m_cookie, sizeof(m_cookie), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

NTSTATUS Endpoint::Connect(PSOCKADDR_INET psi, _In_opt_ PBYTE pb, _In_opt_ ULONG cb)
{
	NTSTATUS status;

	if (NOERROR == (status = Init(psi, 0)))
	{
		SetDisconnectTime(e_inactive_time);

		m_parent->AddConnection(this);

		CDataPacket* packet;
		C_PACKET* pcp;
		if (UH_PACKET* pkt = UH_PACKET::Plain_Create(0, sizeof(C_PACKET) + cb, &packet, (BYTE**)&pcp))
		{
			pkt->cookie = 0;
			pcp->client_cookie = m_cookie;
			if (cb)
			{
				memcpy(pcp->data, pb, cb);
			}
			m_sa = *psi;
			status = m_parent->SendTo(psi, packet);
			packet->Release();
		}
		else
		{
			status = STATUS_NO_MEMORY;
		}

		if (status)
		{
			m_parent->RemoveConnection(this);
		}
	}

	return status;
}

void Endpoint::Disconnect()
{
	DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	m_parent->SendTo(&m_sa, &m_rcookie, sizeof(m_rcookie));
	m_parent->RemoveConnection(this);
}

void Endpoint::ping()
{
	P_PACKET packet = { P_PACKET::e_magic, m_rcookie };
	m_parent->SendTo(&m_sa, &packet, sizeof(packet));
}

Endpoint::MSGB* Endpoint::get(ULONG M, ULONG cbMsg)
{
	ULONG i = e_nb;
	MSGB* msgb = m_msgb, *_msgb = 0, *__msgb = 0;
	ULONG tick = GetTickCount(), _dt = 0, dt;
	do 
	{
		if (msgb->m_M == M)
		{
			return cbMsg == msgb->m_cbMsg ? msgb : 0;
		}

		if (!_msgb && !msgb->m_bits)
		{
			_msgb = msgb;
		}

		if (_dt < (dt = tick - msgb->m_tick))
		{
			_dt = dt;
			if (999 < dt)
			{
				__msgb = msgb;
			}
		}
		
	} while (msgb++, --i);

	if (_msgb || (_msgb = __msgb))
	{
		_msgb->m_cbMsg = cbMsg;
		_msgb->m_cbNeed = cbMsg;
		_msgb->m_M = M;
	}

	return _msgb;
}

NTSTATUS Endpoint::OnData(E_PACKET* packet, ULONG cb)
{
	NTSTATUS status;
	SetDisconnectTime(e_inactive_time);

	AcquireSRWLockExclusive(&m_lock);
	MSGB* msgb = get(packet->M, packet->MsgLength);
	ReleaseSRWLockExclusive(&m_lock);

	if (!msgb)
	{
		return 0;
	}

	LONG N = packet->N;

	DbgPrint("%hs: << %u.%u [%x]\r\n", m_parent->m_name, packet->M, N, cb);

	if (0x40 > N && !_interlockedbittestandset64(&msgb->m_bits, N))
	{
		memcpy(msgb->m_buf + N * max_packet_size, packet->Buf, cb);

		msgb->m_tick = GetTickCount();

		if (InterlockedExchangeAddNoFence(&msgb->m_cbNeed, -(LONG)cb) == (LONG)cb && !((m_bits + 1) & m_bits))
		{
			DbgPrint("%u: ======== %x packet\r\n", GetTickCount() - m_t, packet->M);

			m_t = GetTickCount();

			status = OnUserData(packet->type, msgb->m_buf, packet->MsgLength);

			msgb->m_bits = 0;

			return status;
		}

		return NOERROR;
	}

	return STATUS_BAD_DATA;
}

NTSTATUS Endpoint::Init(PSOCKADDR_INET psi, ULONG64 rcookie)
{
	if (!m_rp.Init())
	{
		return STATUS_INVALID_DEVICE_STATE;
	}

	if (MSGB* msgb = m_msgb)
	{
		__0:
		ULONG n = e_nb;
		do
		{
			msgb->m_M = MAXULONG;
			msgb++->m_bits = 0;
		} while (--n);
	}
	else
	{
		if (msgb = new MSGB[e_nb])
		{
			m_msgb = msgb;
			goto __0;
		}
		else
		{
			return STATUS_NO_MEMORY;
		}
	}

	m_sa = *psi, m_rcookie = rcookie;

	return NOERROR;
}

NTSTATUS Endpoint::SendMsg(ULONG MsgLength, ULONG type, PBYTE pb, ULONG cb, USHORT M, USHORT N)
{
	NTSTATUS status = STATUS_NO_MEMORY;
	CDataPacket* packet;

	union {
		PBYTE pbData;
		E_PACKET* epacket;
	};
	if (UH_PACKET* pkt = UH_PACKET::AES_Allocate(sizeof(E_PACKET) + cb, &pbData, &packet))
	{
		epacket->M = M, epacket->N = N;
		epacket->type = type, epacket->MsgLength = MsgLength;

		memcpy(epacket->Buf, pb, cb);

		if (0 <= (status = pkt->AES_Encode(m_hKey, pbData, sizeof(E_PACKET) + cb)))
		{
			pkt->cookie = m_rcookie;
			status = m_parent->SendTo(&m_sa, packet);
		}

		packet->Release();
	}

	return status;
}

NTSTATUS Endpoint::SendUserData(ULONG type, PBYTE pb, ULONG cb)
{
	if (max_packet_size * 0x40 < cb)
	{
		return STATUS_PORT_MESSAGE_TOO_LONG;
	}

	ULONG s, MsgLength = cb;

	USHORT M = InterlockedIncrementNoFence16(&m_M), N = 0;

	do 
	{
		if (NTSTATUS status = SendMsg(MsgLength, type, pb, s = __min(cb, max_packet_size), M, N++))
		{
			return status;
		}

	} while (pb += s, cb -= s);

	return STATUS_SUCCESS;
}

void Endpoint::notify_disconnect()
{
	if (m_rp.Acquire())
	{
		m_rp.Rundown_l();

		if (m_rp.Release())
		{
			OnDisconnect();
		}
	}
}

//////////////////////////////////////////////////////////////////////////
// CClientServerR

void CClientServerR::AddListen()
{
	if (CDataPacket* packet = new(Endpoint::max_packet_size + sizeof(E_PACKET) + 0x80) CDataPacket)
	{
		if (RecvFrom(packet) == NOERROR)
		{
			InterlockedIncrementNoFence(&m_nPackets);
			DbgPrint("++packet<%p>\r\n", packet);
		}
		packet->Release();
	}
}

BOOL CClientServerR::Start(ULONG n, PSOCKADDR_INET psi)
{
	if (!Create(psi))
	{
		do
		{
			AddListen();
		} while (--n);
		return m_nPackets;
	}
	return FALSE;
}

void CClientServerR::RemoveConnection(Endpoint* p)
{
	AcquireSRWLockExclusive(&m_lock);
	RemoveEntryList(p);
	InitializeListHead(p);
	ReleaseSRWLockExclusive(&m_lock);
	p->notify_disconnect();
	p->Release();
}

void CClientServerR::AddConnection(Endpoint* p)
{
	p->AddRef();
	AcquireSRWLockExclusive(&m_lock);
	InsertHeadList(this, p);
	ReleaseSRWLockExclusive(&m_lock);
}

Endpoint* CClientServerR::get(ULONG64 cookie)
{
	if (cookie)
	{
		AcquireSRWLockShared(&m_lock);
		Endpoint* p = 0;
		PLIST_ENTRY entry = this;
		while(this != (entry = entry->Flink))
		{
			if (cookie == static_cast<Endpoint*>(entry)->m_cookie)
			{
				(p = static_cast<Endpoint*>(entry))->AddRef();
				break;
			}
		}
		ReleaseSRWLockShared(&m_lock);

		return p;
	}

	return 0;
}

void CClientServerR::OnRecv(PSTR buf, ULONG cb, CDataPacket* packet, SOCKADDR_IN_EX* from)
{
	if (buf)
	{
		//PrintIP(&from->addr, cb);

		OnData((PBYTE)buf, cb, &from->addr);

		cb = NOERROR;
	}

	switch (cb)
	{
	case NOERROR:
	case ERROR_PORT_UNREACHABLE:
		if (RecvFrom(packet) == NOERROR)
		{
			//DbgPrint("reuse packet<%p>\r\n", packet);
			return;
		}
	}

	DbgPrint("error = %x\r\n--packet<%p>\r\n", cb, packet);

	if (!InterlockedDecrement(&m_nPackets))
	{
		Stop();
	}
}

void CClientServerR::OnConnect(_In_ ULONG64 client_cookie, _In_ PBYTE pb, _In_ ULONG cb, PSOCKADDR_INET psi)
{
	BCRYPT_KEY_HANDLE hPubKey;

	if (NOERROR == CreatePubKey(&hPubKey, pb, cb))
	{
		if (Endpoint* p = CreateEndpoint())
		{
			AddConnection(p);

			HRESULT hr;

			if (NOERROR == (hr = p->Init(psi, client_cookie)))
			{
				if (NOERROR == (hr = p->Accept(psi)))
				{
					CDataPacket* packet;
					if (NOERROR == (hr = UH_PACKET::Encode(hPubKey,
						(PBYTE)&p->m_cookie, sizeof(p->m_cookie), &packet, &p->m_hKey)))
					{
						UH_PACKET::get(packet)->cookie = client_cookie;
						hr = SendTo(psi, packet);
						packet->Release();
					}
				}
			}

			if (hr)
			{
				RemoveConnection(p);
			}

			p->Release();
		}

		BCryptDestroyKey(hPubKey);
	}
}

void CClientServerR::OnDisconnect(ULONG64 cookie, PSOCKADDR_INET psi)
{
	if (Endpoint* p = get(cookie))
	{
		if (*psi == p->m_sa)
		{
			RemoveConnection(p);
		}
		p->Release();
	}
}

void CClientServerR::OnPing(P_PACKET* packet, PSOCKADDR_INET psi)
{
	if (P_PACKET::e_magic == packet->magic)
	{
		if (Endpoint* p = get(packet->crc))
		{
			if (*psi == p->m_sa)
			{
				p->SetDisconnectTime(Endpoint::e_inactive_time);
			}
			p->Release();
		}
	}
}

void CClientServerR::OnData(PBYTE pb, ULONG cb, PSOCKADDR_INET psi)
{
	switch (cb)
	{
	case sizeof(ULONG64):
		OnDisconnect(*(ULONG64*)pb, psi);
		break;

	case sizeof(P_PACKET):
		OnPing((P_PACKET*)pb, psi);
		break;

	default:
		UH_PACKET* pkt = (UH_PACKET*)pb;
		if (pkt->IsSizeValid(cb))
		{
			if (Endpoint* p = get(pkt->cookie))
			{
				if (*psi == p->m_sa)
				{
					NTSTATUS status = STATUS_TOO_LATE;
					if (p->m_rp.Acquire())
					{
						if (p->m_rcookie)
						{
							if (NOERROR == pkt->AES_Decode(p->m_hKey, &pb, &cb))
							{
								if (sizeof(E_PACKET) <= cb)
								{
									status = p->OnData(reinterpret_cast<E_PACKET*>(pb), cb - sizeof(E_PACKET));
								}
							}
						}
						else
						{
							if (BCRYPT_KEY_HANDLE hKey = p->GetPrivateKey())
							{
								if (NOERROR == pkt->Decode(hKey, &pb, &cb, &p->m_hKey))
								{
									if (sizeof(ULONG64) == cb)
									{
										p->m_rcookie = *(ULONG64*)pb;

										status = p->OnConnect();
									}
								}
							}
						}

						if (p->m_rp.Release())
						{
							p->OnDisconnect();
						}
					}

					if (status)
					{
						RemoveConnection(p);
					}
				}
				p->Release();
			}
			else 
			{
				if (pkt->IsPlainData(&cb, &pb) && sizeof(C_PACKET) < cb)
				{
					OnConnect(reinterpret_cast<C_PACKET*>(pb)->client_cookie,
						reinterpret_cast<C_PACKET*>(pb)->data, cb - sizeof(C_PACKET), psi);
				}
			}
		}
	}
}

void CClientServerR::Stop()
{
	DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);

	AcquireSRWLockExclusive(&m_lock);
	LIST_ENTRY Head = { Flink, Blink };
	Flink->Blink = &Head;
	Blink->Flink = &Head;
	InitializeListHead(this);
	ReleaseSRWLockExclusive(&m_lock);

	PLIST_ENTRY entry = Head.Flink;

	while (&Head != entry)
	{
		Endpoint* p = static_cast<Endpoint*>(entry);
		entry = entry->Flink;
		p->notify_disconnect();
		p->Release();
	}
}

void CClientServerR::deleteTimer()
{
	if (PTP_TIMER Timer = (PTP_TIMER)InterlockedExchangePointer((void**)&_M_Timer, 0))
	{
		TpWaitForTimer(Timer, TRUE);
		TpReleaseTimer(Timer);
	}
}

void CClientServerR::OnTimer()
{
	ULONG64 time = GetTickCount64();
	Endpoint* first = 0;
	AcquireSRWLockExclusive(&m_lock);
	PLIST_ENTRY entry = Flink;
	while (this != entry)
	{
		Endpoint* p = static_cast<Endpoint*>(entry);
		entry = entry->Flink;
		if (p->m_tick < time)
		{
			RemoveEntryList(p);
			InitializeListHead(p);
			p->m_next = first;
			first = p;
		}
	}
	ReleaseSRWLockExclusive(&m_lock);

	while (Endpoint* p = first)
	{
		first = p->m_next;
		p->Disconnect();
		p->Release();
	}
}

VOID NTAPI CClientServerR::_onTimer(
	_Inout_     PTP_CALLBACK_INSTANCE /*Instance*/,
	_Inout_opt_ PVOID                 Context,
	_Inout_     PTP_TIMER             /*Timer*/
)
{
	reinterpret_cast<CClientServerR*>(Context)->OnTimer();
}

NTSTATUS CClientServerR::SetTimer(ULONG Period)
{
	NTSTATUS status = TpAllocTimer(&_M_Timer, _onTimer, this, 0);

	if (0 > status)
	{
		return status;
	}
	LARGE_INTEGER li = {};
	TpSetTimer(_M_Timer, &li, Period, 0);
	return STATUS_SUCCESS;
}

_NT_END