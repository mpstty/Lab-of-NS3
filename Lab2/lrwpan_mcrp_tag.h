#ifndef D_MCRP_PACKET_TAG_H
#define D_MCRP_PACKET_TAG_H

#include <stdint.h>
#include <iostream>
#include <iomanip>
#include <cmath>
#include <ctime>
#include <string>
#include <iterator>
#include <map>
#include <list>

#include "ns3/core-module.h"
#include "ns3/lr-wpan-module.h"
#include "ns3/mobility-module.h"
#include "ns3/sixlowpan-module.h"
#include "ns3/network-module.h"
#include "ns3/spectrum-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"


using namespace ns3;
using namespace std;

class McrpPktTag : public Tag {
private:
   uint16_t    m_infos;//type:Bit 13-15 ~ 2^3-1,  seq:Bit 0-12 ~ 2^13-1=8191
	uint8_t     m_hops;
	uint8_t 		m_address[2];
	double 			m_time; 
	double 			m_rtt;	

public:
	static TypeId GetTypeId (void);
	TypeId GetInstanceTypeId(void) const;
	uint32_t GetSerializedSize(void) const;
	void Serialize(TagBuffer i) const;
	void Deserialize (TagBuffer i);
	void Print(ostream &os) const;

	McrpPktTag();
	~McrpPktTag();

	int GetPktType(void) const;
	int GetPktHops(void) const;
	int GetPktSeq(void) const;
	double GetPktTime(void) const;
	double GetRttTime(void) const;
	Address GetPktAddress() const;
	void SetPktType(int n);
	void SetPktHops(int n);
	void SetPktSeq(int n);
	void SetPktAddress(Address);
	void SetPktTime(double f);
	void SetRttTime(double f);
};

class McrpCache{
public:
	typedef struct{
      int m_seq;
      double m_txtime;
      Address m_srcaddr;//mac
      int m_hops;
      int m_status;
      int m_trys;
      Ipv6Address m_ipv6_srcaddr;
      double m_rxtime;
      double m_rttime;
      double m_xloc;
      double m_yloc;
      Ptr<Packet> m_packet;
      uint8_t *m_data;
      uint32_t m_length;
    }Record;

   McrpCache();
	~McrpCache();
	bool Insert(McrpCache::Record *r);
	bool Insert(McrpCache::Record *r, bool fullcheck);
	bool Insert(int seq, double txt, Address src, Ptr<const Packet> pkt, double rxt);
	McrpCache::Record* Select(int seq, double txt, Address src);
	Ptr<Packet> GetCurrentPacket();
	void Print();
	list<McrpCache::Record *>* GetAllRecords();

private:
	list<McrpCache::Record *>* m_cachelist;
	list<McrpCache::Record *>::iterator m_current_recordit;

};

#endif
