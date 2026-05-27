/*****************************************************************************
Copyright (c) 2001 - 2011, The Board of Trustees of the University of Illinois.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above
  copyright notice, this list of conditions and the
  following disclaimer.

* Redistributions in binary form must reproduce the
  above copyright notice, this list of conditions
  and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the University of Illinois
  nor the names of its contributors may be used to
  endorse or promote products derived from this
  software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*****************************************************************************/

/*****************************************************************************
written by
   Yunhong Gu, last updated 07/09/2011
*****************************************************************************/

#ifdef WINDOWS
   #include <winsock2.h>
   #include <ws2tcpip.h>
   #include <wspiapi.h>
#else
   #include <unistd.h>
#endif
#include <cstring>
#include "api.h"
#include "core.h"

using namespace std;

CUDTSocket::CUDTSocket():
m_Status(INIT),
m_TimeStamp(0),
m_iIPversion(0),
m_pSelfAddr(NULL),
m_pPeerAddr(NULL),
m_SocketID(0),
m_ListenSocket(0),
m_PeerID(0),
m_iISN(0),
m_pUDT(nullptr),
m_pQueuedSockets(),
m_pAcceptSockets(),
m_AcceptLock(),
m_uiBackLog(0),
m_iMuxID(-1)
{}

CUDTSocket::~CUDTSocket()
{
   if (AF_INET == m_iIPversion)
   {
      delete (sockaddr_in*)m_pSelfAddr;
      delete (sockaddr_in*)m_pPeerAddr;
   }
   else
   {
      delete (sockaddr_in6*)m_pSelfAddr;
      delete (sockaddr_in6*)m_pPeerAddr;
   }
}

////////////////////////////////////////////////////////////////////////////////

CUDTUnited::CUDTUnited():
m_Sockets(),
m_ControlLock(),
m_IDLock(),
m_SocketID(0),
m_TLSError(),
m_mMultiplexer(),
m_MultiplexerLock(),
m_pCache(nullptr),
m_GCStopCond(),
m_InitLock(),
m_iInstanceCount(0),
m_bGCStatus(false),
m_GCThread(),
m_ClosedSockets()
{
   // Socket ID MUST start from a random value
   srand((unsigned int)CTimer::getTime());
   m_SocketID = 1 + (int)((1 << 30) * (double(rand()) / RAND_MAX));

   #ifndef WINDOWS
      pthread_key_create(&m_TLSError, TLSDestroy);
   #else
      m_TLSError = TlsAlloc();
   #endif

   m_pCache = std::make_unique<CCache<CInfoBlock>>();
}

CUDTUnited::~CUDTUnited()
{
   #ifndef WINDOWS
      pthread_key_delete(m_TLSError);
   #else
      TlsFree(m_TLSError);
   #endif
}

int CUDTUnited::startup()
{
   std::lock_guard gcinit(m_InitLock);

   if (m_iInstanceCount++ > 0)
      return 0;

   // Global initialization code
   #ifdef WINDOWS
      WORD wVersionRequested;
      WSADATA wsaData;
      wVersionRequested = MAKEWORD(2, 2);

      if (0 != WSAStartup(wVersionRequested, &wsaData))
         throw CUDTException(1, 0,  WSAGetLastError());
   #endif

   if (m_bGCStatus)
      return true;

   m_GCThread = std::thread(garbageCollect, this);

   m_bGCStatus = true;

   return 0;
}

int CUDTUnited::cleanup()
{
   std::lock_guard gcinit(m_InitLock);

   if (--m_iInstanceCount > 0)
      return 0;

   if (!m_bGCStatus)
      return 0;

   m_GCStopCond.set();
   m_GCThread.join();

   m_bGCStatus = false;

   // Global destruction code
   #ifdef WINDOWS
      WSACleanup();
   #endif

   return 0;
}

UDTSOCKET CUDTUnited::newSocket(int af, int type)
{
   if (type != SOCK_DGRAM)
      throw CUDTException(5, 3, 0);

   std::shared_ptr<CUDTSocket> ns;

   try
   {
      ns = std::make_shared<CUDTSocket>();
      ns->m_pUDT = std::make_unique<CUDT>();
      if (AF_INET == af)
      {
         ns->m_pSelfAddr = (sockaddr*)(new sockaddr_in);
         ((sockaddr_in*)(ns->m_pSelfAddr))->sin_port = 0;
      }
      else
      {
         ns->m_pSelfAddr = (sockaddr*)(new sockaddr_in6);
         ((sockaddr_in6*)(ns->m_pSelfAddr))->sin6_port = 0;
      }
   }
   catch (...)
   {
      throw CUDTException(3, 2, 0);
   }

   {
      std::lock_guard guard(m_IDLock);
      ns->m_SocketID = -- m_SocketID;
   }

   ns->m_Status = INIT;
   ns->m_ListenSocket = 0;
   ns->m_pUDT->m_SocketID = ns->m_SocketID;
   ns->m_pUDT->m_iSockType = UDT_DGRAM;
   ns->m_pUDT->m_iIPversion = ns->m_iIPversion = af;
   ns->m_pUDT->m_pCache = m_pCache.get();

   try
   {
      // protect the m_Sockets structure.
      std::lock_guard guard(m_ControlLock);
      m_Sockets[ns->m_SocketID] = ns;
   }
   catch (...)
   {
      //failure and rollback
   }

   if (!ns)
      throw CUDTException(3, 2, 0);

   return ns->m_SocketID;
}

int CUDTUnited::newConnection(const UDTSOCKET listener, const sockaddr* peer, CHandShake* hs)
{
   std::shared_ptr<CUDTSocket> ns;
   auto ls = locate(listener);

   if (!ls)
      return -1;

   // if this connection has already been processed
   if ((ns = locate(peer, hs->m_iID, hs->m_iISN)))
   {
      if (ns->m_pUDT->m_bBroken)
      {
         // last connection from the "peer" address has been broken
         ns->m_Status = CLOSED;
         ns->m_TimeStamp = CTimer::getTime();

         std::lock_guard guard(ls->m_AcceptLock);
         ls->m_pQueuedSockets.erase(ns->m_SocketID);
         ls->m_pAcceptSockets.erase(ns->m_SocketID);
      }
      else
      {
         // connection already exist, this is a repeated connection request
         // respond with existing HS information

         hs->m_iISN = ns->m_pUDT->m_iISN;
         hs->m_iMSS = ns->m_pUDT->m_iMSS;
         hs->m_iFlightFlagSize = ns->m_pUDT->m_iFlightFlagSize;
         hs->m_iReqType = -1;
         hs->m_iID = ns->m_SocketID;

         return 0;

         //except for this situation a new connection should be started
      }
   }

   // exceeding backlog, refuse the connection request
   if (ls->m_pQueuedSockets.size() >= ls->m_uiBackLog)
      return -1;

   try
   {
      ns = std::make_shared<CUDTSocket>();
      ns->m_pUDT = std::make_unique<CUDT>(*(ls->m_pUDT));
      if (AF_INET == ls->m_iIPversion)
      {
         ns->m_pSelfAddr = (sockaddr*)(new sockaddr_in);
         ((sockaddr_in*)(ns->m_pSelfAddr))->sin_port = 0;
         ns->m_pPeerAddr = (sockaddr*)(new sockaddr_in);
         memcpy(ns->m_pPeerAddr, peer, sizeof(sockaddr_in));
      }
      else
      {
         ns->m_pSelfAddr = (sockaddr*)(new sockaddr_in6);
         ((sockaddr_in6*)(ns->m_pSelfAddr))->sin6_port = 0;
         ns->m_pPeerAddr = (sockaddr*)(new sockaddr_in6);
         memcpy(ns->m_pPeerAddr, peer, sizeof(sockaddr_in6));
      }
   }
   catch (...)
   {
      return -1;
   }

   {
      std::lock_guard guard(m_IDLock);
      ns->m_SocketID = -- m_SocketID;
   }

   ns->m_ListenSocket = listener;
   ns->m_iIPversion = ls->m_iIPversion;
   ns->m_pUDT->m_SocketID = ns->m_SocketID;
   ns->m_PeerID = hs->m_iID;
   ns->m_iISN = hs->m_iISN;

   int error = 0;

   try
   {
      // bind to the same addr of listening socket
      ns->m_pUDT->open();
      updateMux(ns.get(), ls.get());
      ns->m_pUDT->connect(peer, hs);
   }
   catch (...)
   {
      error = 1;
      goto ERR_ROLLBACK;
   }

   ns->m_Status = CONNECTED;

   // copy address information of local node
   ns->m_pUDT->m_pSndQueue->m_pChannel->getSockAddr(ns->m_pSelfAddr);
   CIPAddress::pton(ns->m_pSelfAddr, ns->m_pUDT->m_piSelfIP, ns->m_iIPversion);

   {
      // protect the m_Sockets structure.
      std::lock_guard guard(m_ControlLock);
      try
      {
         m_Sockets[ns->m_SocketID] = ns;
         m_PeerRec[(ns->m_PeerID << 30) + ns->m_iISN].insert(ns->m_SocketID);
      }
      catch (...)
      {
         error = 2;
      }
   }

   {
      try
      {
         std::lock_guard guard(ls->m_AcceptLock);
         ls->m_pQueuedSockets.insert(ns->m_SocketID);
      }
      catch (...)
      {
         error = 3;
      }
   }

   // acknowledge users waiting for new connections on the listening socket
   m_RPoll->update_events(listener, UDT_EPOLL_IN, true);

   ERR_ROLLBACK:
   if (error > 0)
   {
      ns->m_pUDT->close();
      ns->m_Status = CLOSED;
      ns->m_TimeStamp = CTimer::getTime();

      return -1;
   }

   return 1;
}

CUDT& CUDTUnited::lookup(const UDTSOCKET u)
{
   // protects the m_Sockets structure
   std::lock_guard cg(m_ControlLock);

   auto i = m_Sockets.find(u);

   if ((i == m_Sockets.end()) || (i->second->m_Status == CLOSED))
      throw CUDTException(5, 4, 0);

   return *i->second->m_pUDT;
}

UDTSTATUS CUDTUnited::getStatus(const UDTSOCKET u)
{
   // protects the m_Sockets structure
   std::lock_guard cg(m_ControlLock);

   auto i = m_Sockets.find(u);

   if (i == m_Sockets.end())
   {
      if (m_ClosedSockets.find(u) != m_ClosedSockets.end())
         return CLOSED;

      return NONEXIST;
   }

   if (i->second->m_pUDT->m_bBroken)
      return BROKEN;

   return i->second->m_Status;
}

int CUDTUnited::bind(const UDTSOCKET u, const sockaddr* name, int namelen)
{
   auto s = locate(u);
   if (!s)
      throw CUDTException(5, 4, 0);

   std::lock_guard cg(s->m_ControlLock);

   // cannot bind a socket more than once
   if (INIT != s->m_Status)
      throw CUDTException(5, 0, 0);

   // check the size of SOCKADDR structure
   if (AF_INET == s->m_iIPversion)
   {
      if (namelen != sizeof(sockaddr_in))
         throw CUDTException(5, 3, 0);
   }
   else
   {
      if (namelen != sizeof(sockaddr_in6))
         throw CUDTException(5, 3, 0);
   }

   s->m_pUDT->open();
   updateMux(s.get(), name);
   s->m_Status = OPENED;

   // copy address information of local node
   s->m_pUDT->m_pSndQueue->m_pChannel->getSockAddr(s->m_pSelfAddr);

   return 0;
}

int CUDTUnited::listen(const UDTSOCKET u, int backlog)
{
   auto s = locate(u);
   if (!s)
      throw CUDTException(5, 4, 0);

   std::lock_guard cg(s->m_ControlLock);

   // do nothing if the socket is already listening
   if (LISTENING == s->m_Status)
      return 0;

   // a socket can listen only if is in OPENED status
   if (OPENED != s->m_Status)
      throw CUDTException(5, 5, 0);

   // listen is not supported in rendezvous connection setup
   if (s->m_pUDT->m_bRendezvous)
      throw CUDTException(5, 7, 0);

   if (backlog <= 0)
      throw CUDTException(5, 3, 0);

   s->m_uiBackLog = backlog;

   try
   {
      s->m_pQueuedSockets.clear();
      s->m_pAcceptSockets.clear();
   }
   catch (...)
   {
      throw CUDTException(3, 2, 0);
   }

   s->m_pUDT->listen();

   s->m_Status = LISTENING;

   return 0;
}

UDTSOCKET CUDTUnited::accept(const UDTSOCKET listener, sockaddr* addr, int* addrlen)
{
   if ((NULL != addr) && (NULL == addrlen))
      throw CUDTException(5, 3, 0);

   auto ls = locate(listener);

   if (!ls)
      throw CUDTException(5, 4, 0);

   // the "listen" socket must be in LISTENING status
   if (LISTENING != ls->m_Status)
      throw CUDTException(5, 6, 0);

   // no "accept" in rendezvous connection setup
   if (ls->m_pUDT->m_bRendezvous)
      throw CUDTException(5, 7, 0);

   UDTSOCKET u = CUDT::INVALID_SOCK;

   // !!only one conection can be set up each time!!

   {
      std::lock_guard guard(ls->m_AcceptLock);
      if (ls->m_pQueuedSockets.size() > 0)
      {
         u = *(ls->m_pQueuedSockets.begin());
         ls->m_pAcceptSockets.insert(ls->m_pAcceptSockets.end(), u);
         ls->m_pQueuedSockets.erase(ls->m_pQueuedSockets.begin());
      }
   }

   if (u == CUDT::INVALID_SOCK)
   {
      // non-blocking receiving, no connection available
      throw CUDTException(6, 2, 0);
   }

   m_RPoll->update_events(u, 0, false);

   if ((addr != NULL) && (addrlen != NULL))
   {
      if (AF_INET == locate(u)->m_iIPversion)
         *addrlen = sizeof(sockaddr_in);
      else
         *addrlen = sizeof(sockaddr_in6);

      // copy address information of peer node
      memcpy(addr, locate(u)->m_pPeerAddr, *addrlen);
   }

   return u;
}

int CUDTUnited::connect(const UDTSOCKET u, const sockaddr* name, int namelen)
{
   auto s = locate(u);
   if (!s)
      throw CUDTException(5, 4, 0);

   std::lock_guard cg(s->m_ControlLock);

   // check the size of SOCKADDR structure
   if (AF_INET == s->m_iIPversion)
   {
      if (namelen != sizeof(sockaddr_in))
         throw CUDTException(5, 3, 0);
   }
   else
   {
      if (namelen != sizeof(sockaddr_in6))
         throw CUDTException(5, 3, 0);
   }

   // a socket can "connect" only if it is in INIT or OPENED status
   if (INIT == s->m_Status)
   {
      if (!s->m_pUDT->m_bRendezvous)
      {
         s->m_pUDT->open();
         updateMux(s.get());
         s->m_Status = OPENED;
      }
      else
         throw CUDTException(5, 8, 0);
   }
   else if (OPENED != s->m_Status)
      throw CUDTException(5, 2, 0);

   // connect_complete() may be called before connect() returns.
   // So we need to update the status before connect() is called,
   // otherwise the status may be overwritten with wrong value (CONNECTED vs. CONNECTING).
   s->m_Status = CONNECTING;
   try
   {
      s->m_pUDT->connect(name);
   }
   catch (CUDTException e)
   {
      s->m_Status = OPENED;
      throw e;
   }

   // record peer address
   delete s->m_pPeerAddr;
   if (AF_INET == s->m_iIPversion)
   {
      s->m_pPeerAddr = (sockaddr*)(new sockaddr_in);
      memcpy(s->m_pPeerAddr, name, sizeof(sockaddr_in));
   }
   else
   {
      s->m_pPeerAddr = (sockaddr*)(new sockaddr_in6);
      memcpy(s->m_pPeerAddr, name, sizeof(sockaddr_in6));
   }

   return 0;
}

void CUDTUnited::connect_complete(const UDTSOCKET u)
{
   auto s = locate(u);
   if (!s)
      throw CUDTException(5, 4, 0);

   // copy address information of local node
   // the local port must be correctly assigned BEFORE CUDT::connect(),
   // otherwise if connect() fails, the multiplexer cannot be located by garbage collection and will cause leak
   s->m_pUDT->m_pSndQueue->m_pChannel->getSockAddr(s->m_pSelfAddr);
   CIPAddress::pton(s->m_pSelfAddr, s->m_pUDT->m_piSelfIP, s->m_iIPversion);

   s->m_Status = CONNECTED;
}

int CUDTUnited::close(const UDTSOCKET u)
{
   auto s = locate(u);
   if (!s)
      throw CUDTException(5, 4, 0);

   std::lock_guard socket_cg(s->m_ControlLock);

   if (s->m_Status == LISTENING)
   {
      if (s->m_pUDT->m_bBroken)
         return 0;

      s->m_TimeStamp = CTimer::getTime();
      s->m_pUDT->m_bBroken = true;

      return 0;
   }

   s->m_pUDT->close();

   // synchronize with garbage collection.
   std::lock_guard manager_cg(m_ControlLock);

   // since "s" is located before m_ControlLock, locate it again in case it became invalid
   auto i = m_Sockets.find(u);
   if ((i == m_Sockets.end()) || (i->second->m_Status == CLOSED))
      return 0;
   s = i->second;

   s->m_Status = CLOSED;

   // a socket will not be immediated removed when it is closed
   // in order to prevent other methods from accessing invalid address
   // a timer is started and the socket will be removed after approximately 1 second
   s->m_TimeStamp = CTimer::getTime();

   m_Sockets.erase(s->m_SocketID);
   m_ClosedSockets[s->m_SocketID] = s;

   return 0;
}

int CUDTUnited::getpeername(const UDTSOCKET u, sockaddr* name, int* namelen)
{
   if (CONNECTED != getStatus(u))
      throw CUDTException(2, 2, 0);

   auto s = locate(u);

   if (!s)
      throw CUDTException(5, 4, 0);

   if (!s->m_pUDT->m_bConnected || s->m_pUDT->m_bBroken)
      throw CUDTException(2, 2, 0);

   if (AF_INET == s->m_iIPversion)
      *namelen = sizeof(sockaddr_in);
   else
      *namelen = sizeof(sockaddr_in6);

   // copy address information of peer node
   memcpy(name, s->m_pPeerAddr, *namelen);

   return 0;
}

int CUDTUnited::getsockname(const UDTSOCKET u, sockaddr* name, int* namelen)
{
   auto s = locate(u);

   if (!s)
      throw CUDTException(5, 4, 0);

   if (s->m_pUDT->m_bBroken)
      throw CUDTException(5, 4, 0);

   if (INIT == s->m_Status)
      throw CUDTException(2, 2, 0);

   if (AF_INET == s->m_iIPversion)
      *namelen = sizeof(sockaddr_in);
   else
      *namelen = sizeof(sockaddr_in6);

   // copy address information of local node
   memcpy(name, s->m_pSelfAddr, *namelen);

   return 0;
}

std::shared_ptr<CUDTSocket> CUDTUnited::locate(const UDTSOCKET u)
{
   std::lock_guard cg(m_ControlLock);

   auto i = m_Sockets.find(u);

   if ((i == m_Sockets.end()) || (i->second->m_Status == CLOSED))
      return nullptr;

   return i->second;
}

std::shared_ptr<CUDTSocket> CUDTUnited::locate(const sockaddr* peer, const UDTSOCKET id, int32_t isn)
{
   std::lock_guard cg(m_ControlLock);

   auto i = m_PeerRec.find((id << 30) + isn);
   if (i == m_PeerRec.end())
      return nullptr;

   for (const auto& j : i->second)
   {
      auto k = m_Sockets.find(j);
      // this socket might have been closed and moved m_ClosedSockets
      if (k == m_Sockets.end())
         continue;

      if (CIPAddress::ipcmp(peer, k->second->m_pPeerAddr, k->second->m_iIPversion))
         return k->second;
   }

   return nullptr;
}

void CUDTUnited::checkBrokenSockets()
{
   std::lock_guard cg(m_ControlLock);

   // set of sockets To Be Closed and To Be Removed
   vector<UDTSOCKET> tbc;
   vector<UDTSOCKET> tbr;

   for (const auto& i : m_Sockets)
   {
      // check broken connection
      if (i.second->m_pUDT->m_bBroken)
      {
         if (i.second->m_Status == LISTENING)
         {
            // for a listening socket, it should wait an extra 3 seconds in case a client is connecting
            if (CTimer::getTime() - i.second->m_TimeStamp < 3000000)
               continue;
         }
         else if ((i.second->m_pUDT->m_pRcvBuffer != NULL) && (i.second->m_pUDT->m_pRcvBuffer->getRcvDataSize() > 0) && (i.second->m_pUDT->m_iBrokenCounter -- > 0))
         {
            // if there is still data in the receiver buffer, wait longer
            continue;
         }

         //close broken connections and start removal timer
         i.second->m_Status = CLOSED;
         i.second->m_TimeStamp = CTimer::getTime();
         tbc.push_back(i.first);
         m_ClosedSockets[i.first] = i.second;

         // remove from listener's queue
         auto ls = m_Sockets.find(i.second->m_ListenSocket);
         if (ls == m_Sockets.end())
         {
            ls = m_ClosedSockets.find(i.second->m_ListenSocket);
            if (ls == m_ClosedSockets.end())
               continue;
         }

         {
            std::lock_guard guard(ls->second->m_AcceptLock);
            ls->second->m_pQueuedSockets.erase(i.second->m_SocketID);
            ls->second->m_pAcceptSockets.erase(i.second->m_SocketID);
         }
      }
   }

   for (const auto& j : m_ClosedSockets)
   {
      if (!j.second->m_bIsExpiring) {
         j.second->m_bIsExpiring = true;
         j.second->m_TimeStamp = CTimer::getTime();
      }

      // timeout 1 second to destroy a socket AND it has been removed from RcvUList
      if ((CTimer::getTime() - j.second->m_TimeStamp > 1000000) && ((NULL == j.second->m_pUDT->m_pRNode) || !j.second->m_pUDT->m_pRNode->m_bOnList))
      {
         tbr.push_back(j.first);
      }
   }

   // move closed sockets to the ClosedSockets structure
   for (const auto& k : tbc)
      m_Sockets.erase(k);

   // remove those timeout sockets
   for (const auto& l : tbr)
      removeSocket(l);
}

void CUDTUnited::removeSocket(const UDTSOCKET u)
{
   auto i = m_ClosedSockets.find(u);

   // invalid socket ID
   if (i == m_ClosedSockets.end())
      return;

   // decrease multiplexer reference count, and remove it if necessary
   const int mid = i->second->m_iMuxID;

   {
      std::lock_guard guard(i->second->m_AcceptLock);
      // if it is a listener, close all un-accepted sockets in its queue and remove them later
      for (const auto& q : i->second->m_pQueuedSockets)
      {
         m_Sockets[q]->m_pUDT->m_bBroken = true;
         m_Sockets[q]->m_pUDT->close();
         m_Sockets[q]->m_TimeStamp = CTimer::getTime();
         m_Sockets[q]->m_Status = CLOSED;
         m_ClosedSockets[q] = m_Sockets[q];
         m_Sockets.erase(q);
      }
   }

   // remove from peer rec
   auto j = m_PeerRec.find((i->second->m_PeerID << 30) + i->second->m_iISN);
   if (j != m_PeerRec.end())
   {
      j->second.erase(u);
      if (j->second.empty())
         m_PeerRec.erase(j);
   }

   // delete this one
   i->second->m_pUDT->close();
   m_ClosedSockets.erase(i);

   auto m = m_mMultiplexer.find(mid);
   if (m == m_mMultiplexer.end())
   {
      //something is wrong!!!
      return;
   }

   m->second.m_iRefCount --;
   if (0 == m->second.m_iRefCount)
   {
      m->second.m_pChannel->close();
      delete m->second.m_pSndQueue;
      delete m->second.m_pRcvQueue;
      delete m->second.m_pTimer;
      delete m->second.m_pChannel;
      m_mMultiplexer.erase(m);
   }
}

void CUDTUnited::setError(CUDTException* e)
{
   #ifndef WINDOWS
      delete (CUDTException*)pthread_getspecific(m_TLSError);
      pthread_setspecific(m_TLSError, e);
   #else
      std::lock_guard tg(m_TLSLock);
      delete (CUDTException*)TlsGetValue(m_TLSError);
      TlsSetValue(m_TLSError, e);
      m_mTLSRecord[GetCurrentThreadId()] = e;
   #endif
}

void CUDTUnited::setError(int major, int minor)
{
   #ifndef WINDOWS
      CUDTException* ex = (CUDTException*)pthread_getspecific(m_TLSError);
      if (!ex || ex->getErrorCode() != major*1000 + minor) {
         delete ex;
         auto e = new CUDTException(major, minor, 0);
         pthread_setspecific(m_TLSError, e);
      }
   #else
      std::lock_guard tg(m_TLSLock);
      CUDTException* ex = (CUDTException*)TlsGetValue(m_TLSError);
      if (!ex || ex->getErrorCode() != major*1000 + minor) {
         delete ex;
         auto e = new CUDTException(major, minor, 0);
         TlsSetValue(m_TLSError, e);
         m_mTLSRecord[GetCurrentThreadId()] = e;
      }
   #endif
}

rpoll::RPoll const &CUDTUnited::getrpoll() { return *m_RPoll; }

CUDTException* CUDTUnited::getError()
{
   #ifndef WINDOWS
      if(NULL == pthread_getspecific(m_TLSError))
         pthread_setspecific(m_TLSError, new CUDTException);
      return (CUDTException*)pthread_getspecific(m_TLSError);
   #else
      std::lock_guard tg(m_TLSLock);
      if(NULL == TlsGetValue(m_TLSError))
      {
         CUDTException* e = new CUDTException;
         TlsSetValue(m_TLSError, e);
         m_mTLSRecord[GetCurrentThreadId()] = e;
      }
      return (CUDTException*)TlsGetValue(m_TLSError);
   #endif
}

#ifdef WINDOWS
void CUDTUnited::checkTLSValue()
{
   std::lock_guard tg(m_TLSLock);

   vector<DWORD> tbr;
   for (const auto& i : m_mTLSRecord)
   {
      HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, i.first);
      if (NULL == h)
      {
         tbr.push_back(i.first);
         break;
      }
      if (WAIT_OBJECT_0 == WaitForSingleObject(h, 0))
      {
         delete i.second;
         tbr.push_back(i.first);
      }
      CloseHandle(h);
   }
   for (const auto& j : tbr)
      m_mTLSRecord.erase(j);
}
#endif

void CUDTUnited::updateMux(CUDTSocket* s, const sockaddr* addr, const UDPSOCKET* udpsock)
{
   std::lock_guard cg(m_ControlLock);

   if ((s->m_pUDT->m_bReuseAddr) && (NULL != addr))
   {
      int port = (AF_INET == s->m_pUDT->m_iIPversion) ? ntohs(((sockaddr_in*)addr)->sin_port) : ntohs(((sockaddr_in6*)addr)->sin6_port);

      // find a reusable address
      for (auto& i : m_mMultiplexer)
      {
         if ((i.second.m_iIPversion == s->m_pUDT->m_iIPversion) && (i.second.m_iMSS == s->m_pUDT->m_iMSS) && i.second.m_bReusable)
         {
            if (i.second.m_iPort == port)
            {
               // reuse the existing multiplexer
               ++ i.second.m_iRefCount;
               s->m_pUDT->m_pSndQueue = i.second.m_pSndQueue;
               s->m_pUDT->m_pRcvQueue = i.second.m_pRcvQueue;
               s->m_iMuxID = i.second.m_iID;
               return;
            }
         }
      }
   }

   // a new multiplexer is needed
   CMultiplexer m;
   m.m_iMSS = s->m_pUDT->m_iMSS;
   m.m_iIPversion = s->m_pUDT->m_iIPversion;
   m.m_iRefCount = 1;
   m.m_bReusable = s->m_pUDT->m_bReuseAddr;
   m.m_iID = s->m_SocketID;

   m.m_pChannel = new CChannel(s->m_pUDT->m_iIPversion);
   m.m_pChannel->setSndBufSize(s->m_pUDT->m_iUDPSndBufSize);
   m.m_pChannel->setRcvBufSize(s->m_pUDT->m_iUDPRcvBufSize);

   try
   {
      if (NULL != udpsock)
         m.m_pChannel->open(*udpsock);
      else
         m.m_pChannel->open(addr);
   }
   catch (CUDTException& e)
   {
      m.m_pChannel->close();
      delete m.m_pChannel;
      throw e;
   }

   sockaddr* sa = (AF_INET == s->m_pUDT->m_iIPversion) ? (sockaddr*) new sockaddr_in : (sockaddr*) new sockaddr_in6;
   m.m_pChannel->getSockAddr(sa);
   m.m_iPort = (AF_INET == s->m_pUDT->m_iIPversion) ? ntohs(((sockaddr_in*)sa)->sin_port) : ntohs(((sockaddr_in6*)sa)->sin6_port);
   if (AF_INET == s->m_pUDT->m_iIPversion) delete (sockaddr_in*)sa; else delete (sockaddr_in6*)sa;

   m.m_pTimer = new CTimer;

   m.m_pSndQueue = new CSndQueue;
   m.m_pSndQueue->init(m.m_pChannel, m.m_pTimer);
   m.m_pRcvQueue = new CRcvQueue;
   m.m_pRcvQueue->init(32, s->m_pUDT->m_iPayloadSize, m.m_iIPversion, 1024, m.m_pChannel, m.m_pTimer);

   m_mMultiplexer[m.m_iID] = m;

   s->m_pUDT->m_pSndQueue = m.m_pSndQueue;
   s->m_pUDT->m_pRcvQueue = m.m_pRcvQueue;
   s->m_iMuxID = m.m_iID;
}

void CUDTUnited::updateMux(CUDTSocket* s, const CUDTSocket* ls)
{
   std::lock_guard cg(m_ControlLock);

   int port = (AF_INET == ls->m_iIPversion) ? ntohs(((sockaddr_in*)ls->m_pSelfAddr)->sin_port) : ntohs(((sockaddr_in6*)ls->m_pSelfAddr)->sin6_port);

   // find the listener's address
   for (auto& i : m_mMultiplexer)
   {
      if (i.second.m_iPort == port)
      {
         // reuse the existing multiplexer
         ++ i.second.m_iRefCount;
         s->m_pUDT->m_pSndQueue = i.second.m_pSndQueue;
         s->m_pUDT->m_pRcvQueue = i.second.m_pRcvQueue;
         s->m_iMuxID = i.second.m_iID;
         return;
      }
   }
}

void CUDTUnited::garbageCollect(CUDTUnited* self)
{
   do
   {
      self->checkBrokenSockets();

      #ifdef WINDOWS
         self->checkTLSValue();
      #endif

      
   } while (!self->m_GCStopCond.wait_for(std::chrono::seconds(1)));

   // remove all sockets and multiplexers
   {
      std::lock_guard guard(self->m_ControlLock);
      for (const auto& i : self->m_Sockets)
      {
         i.second->m_pUDT->m_bBroken = true;
         i.second->m_pUDT->close();
         i.second->m_Status = CLOSED;
         i.second->m_TimeStamp = CTimer::getTime();
         self->m_ClosedSockets[i.first] = i.second;

         // remove from listener's queue
         auto ls = self->m_Sockets.find(i.second->m_ListenSocket);
         if (ls == self->m_Sockets.end())
         {
            ls = self->m_ClosedSockets.find(i.second->m_ListenSocket);
            if (ls == self->m_ClosedSockets.end())
               continue;
         }

         std::lock_guard guard(ls->second->m_AcceptLock);
         ls->second->m_pQueuedSockets.erase(i.second->m_SocketID);
         ls->second->m_pAcceptSockets.erase(i.second->m_SocketID);
      }
      self->m_Sockets.clear();

      for (const auto& j : self->m_ClosedSockets)
      {
         j.second->m_TimeStamp = 0;
      }
   }

   while (true)
   {
      self->checkBrokenSockets();

      bool empty;
      {
         std::lock_guard guard(self->m_ControlLock);
         empty = self->m_ClosedSockets.empty();
      }

      if (empty)
         break;

      CTimer::sleep();
   }
}

////////////////////////////////////////////////////////////////////////////////

int CUDT::startup()
{
   return s_UDTUnited.startup();
}

int CUDT::cleanup()
{
   return s_UDTUnited.cleanup();
}

UDTSOCKET CUDT::socket(int af, int type, int)
{
   if (!s_UDTUnited.m_bGCStatus)
      s_UDTUnited.startup();

   try
   {
      return s_UDTUnited.newSocket(af, type);
   }
   catch (CUDTException& e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return INVALID_SOCK;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(3, 2);
      return INVALID_SOCK;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return INVALID_SOCK;
   }
}

int CUDT::bind(UDTSOCKET u, const sockaddr* name, int namelen)
{
   try
   {
      return s_UDTUnited.bind(u, name, namelen);
   }
   catch (CUDTException& e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(3, 2);
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

int CUDT::listen(UDTSOCKET u, int backlog)
{
   try
   {
      return s_UDTUnited.listen(u, backlog);
   }
   catch (CUDTException& e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(3, 2);
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

UDTSOCKET CUDT::accept(UDTSOCKET u, sockaddr* addr, int* addrlen)
{
   try
   {
      return s_UDTUnited.accept(u, addr, addrlen);
   }
   catch (CUDTException& e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return INVALID_SOCK;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return INVALID_SOCK;
   }
}

int CUDT::connect(UDTSOCKET u, const sockaddr* name, int namelen)
{
   try
   {
      return s_UDTUnited.connect(u, name, namelen);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(3, 2);
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

int CUDT::close(UDTSOCKET u)
{
   try
   {
      return s_UDTUnited.close(u);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

int CUDT::getpeername(UDTSOCKET u, sockaddr* name, int* namelen)
{
   try
   {
      return s_UDTUnited.getpeername(u, name, namelen);
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

int CUDT::getsockname(UDTSOCKET u, sockaddr* name, int* namelen)
{
   try
   {
      return s_UDTUnited.getsockname(u, name, namelen);;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

int CUDT::getsockopt(UDTSOCKET u, int, UDTOpt optname, void* optval, int* optlen)
{
   try
   {
      CUDT& udt = s_UDTUnited.lookup(u);
      udt.getOpt(optname, optval, *optlen);
      return 0;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

int CUDT::setsockopt(UDTSOCKET u, int, UDTOpt optname, const void* optval, int optlen)
{
   try
   {
      CUDT& udt = s_UDTUnited.lookup(u);
      udt.setOpt(optname, optval, optlen);
      return 0;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

int CUDT::sendmsg(UDTSOCKET u, const char* buf, int len, int ttl, bool inorder)
{
   try
   {
      CUDT& udt = s_UDTUnited.lookup(u);
      int res = udt.sendmsg(buf, len, ttl, inorder);

      // r: hot path optimization.
      if (res < 0) {
         res = -res;
         s_UDTUnited.setError(
            res / 1000,
            res % 1000
         );
         return ERROR;
      }
      return res;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (bad_alloc&)
   {
      s_UDTUnited.setError(3, 2);
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

int CUDT::recvmsg(UDTSOCKET u, char* buf, int len)
{
   try
   {
      CUDT& udt = s_UDTUnited.lookup(u);
      int res = udt.recvmsg(buf, len);

      // r: hot path optimization. C++ exceptions are *really* slow.
      if (res < 0) {
         res = -res;
         s_UDTUnited.setError(
            res / 1000,
            res % 1000
         );
         return ERROR;
      }
      return res;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

rpoll::RPoll const &CUDT::getrpoll() { return s_UDTUnited.getrpoll(); }

CUDTException& CUDT::getlasterror()
{
   return *s_UDTUnited.getError();
}

int CUDT::perfmon(UDTSOCKET u, CPerfMon& perf, bool clear)
{
   try
   {
      CUDT& udt = s_UDTUnited.lookup(u);
      udt.sample(perf, clear);
      return 0;
   }
   catch (CUDTException e)
   {
      s_UDTUnited.setError(new CUDTException(e));
      return ERROR;
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return ERROR;
   }
}

CUDT* CUDT::getUDTHandle(UDTSOCKET u)
{
   try
   {
      return &s_UDTUnited.lookup(u);
   }
   catch (...)
   {
      return NULL;
   }
}

UDTSTATUS CUDT::getsockstate(UDTSOCKET u)
{
   try
   {
      return s_UDTUnited.getStatus(u);
   }
   catch (...)
   {
      s_UDTUnited.setError(-1, 0);
      return NONEXIST;
   }
}


////////////////////////////////////////////////////////////////////////////////

namespace UDT
{

int startup()
{
   return CUDT::startup();
}

int cleanup()
{
   return CUDT::cleanup();
}

UDTSOCKET socket(int af, int type, int protocol)
{
   return CUDT::socket(af, type, protocol);
}

int bind(UDTSOCKET u, const struct sockaddr* name, int namelen)
{
   return CUDT::bind(u, name, namelen);
}

int listen(UDTSOCKET u, int backlog)
{
   return CUDT::listen(u, backlog);
}

UDTSOCKET accept(UDTSOCKET u, struct sockaddr* addr, int* addrlen)
{
   return CUDT::accept(u, addr, addrlen);
}

int connect(UDTSOCKET u, const struct sockaddr* name, int namelen)
{
   return CUDT::connect(u, name, namelen);
}

int close(UDTSOCKET u)
{
   return CUDT::close(u);
}

int getpeername(UDTSOCKET u, struct sockaddr* name, int* namelen)
{
   return CUDT::getpeername(u, name, namelen);
}

int getsockname(UDTSOCKET u, struct sockaddr* name, int* namelen)
{
   return CUDT::getsockname(u, name, namelen);
}

int getsockopt(UDTSOCKET u, int level, SOCKOPT optname, void* optval, int* optlen)
{
   return CUDT::getsockopt(u, level, optname, optval, optlen);
}

int setsockopt(UDTSOCKET u, int level, SOCKOPT optname, const void* optval, int optlen)
{
   return CUDT::setsockopt(u, level, optname, optval, optlen);
}

int sendmsg(UDTSOCKET u, const char* buf, int len, int ttl, bool inorder)
{
   return CUDT::sendmsg(u, buf, len, ttl, inorder);
}

int recvmsg(UDTSOCKET u, char* buf, int len)
{
   return CUDT::recvmsg(u, buf, len);
}

const rpoll::RPoll &getrpoll() { return CUDT::getrpoll(); }

ERRORINFO& getlasterror()
{
   return CUDT::getlasterror();
}

int getlasterror_code()
{
   return CUDT::getlasterror().getErrorCode();
}

const std::string &getlasterror_desc()
{
   return CUDT::getlasterror().getErrorMessage();
}

int perfmon(UDTSOCKET u, TRACEINFO& perf, bool clear)
{
   return CUDT::perfmon(u, perf, clear);
}

UDTSTATUS getsockstate(UDTSOCKET u)
{
   return CUDT::getsockstate(u);
}

}  // namespace UDT
