#ifndef WSN_MAC_ROUTING_H
#define WSN_MAC_ROUTING_H
#include "ns3/point-to-point-module.h"
#include "lrwpan_mcrp_tag.h"

using namespace ns3;
using namespace std;

class MacCentredRoutingProtocol{
public:
	typedef struct{
		int seq;
		int hops;
		Address mine;
		Address dest;
		Address next;
		//int64_t rtt; //in nano seconds
		double rtt; //in seconds
		double dist;
		double calt;
		double ratio;
		int flag;
   }Route;

	MacCentredRoutingProtocol(Ptr<NetDevice>);
	~MacCentredRoutingProtocol();

	void TxDataConfirmNotification(McpsDataConfirmParams);
	void CreateRouteTable();
	void DeleteRouteTable();
	void PrintRouteTable(Ptr<OutputStreamWrapper>);
	void PrintRoutes(Ptr<OutputStreamWrapper> stream);
	void SetRxDataTrace(Callback< void, double, Ptr<const Packet>, Ptr<Node> >);
	McrpPktTag* GetTagFromPacket(Ptr<const Packet> pkt);

	Ptr<Node> GetNode(){return m_node;}
	Vector GetPosition(){return m_position;}
	void CalculateRtt(MacCentredRoutingProtocol::Route *route);
	void SetIdle();
	void SetBusyFor(double);
	bool IsBusy();
	void StartZeroRoute(double now);
	Address LookupMcrpRoute(Address& dest);
	bool HasMcrpRoute(Address dest);
	void SendRequest(double now);
	int Transmit(double now, Ptr<Packet> pkt, Address dst, bool forward);
	bool Receiver(Ptr<NetDevice>, Ptr<const Packet>, uint16_t, const Address&);
	void InsertRoute(Address dest, Address next, int hops, int flag);

	bool ReceiveFromPeer(Ptr<NetDevice>, Ptr<const Packet>, uint16_t, const Address&);
	void SendToPeer(int hops);
	bool UpdateMaliciousRoute(Address dest, Address next, int hops);
	bool DeleteMaliciousRoute(Address dest, Address next, int hops);

	void ReceiveRequest(double now, McrpPktTag* tag, const Address& src);
	void SendResponse(int hops);
	void SendResponse(int hops,double);
	void ReceiveResponse(double now, McrpPktTag* tag, const Address& src);
	bool UpdateRoute(Address dest, Address next, int hops);
	bool UpdateRoute(Address dest, Address next, int hops,double, double*);
	void ReceiveData(double now, Ptr<const Packet> pkt, McrpPktTag* tag, const Address&);
	void SetMaliciousPeer(Address peer);
	void SetPeerIpv4Address(Ipv4Address peer);
	void RecvIpv4Packets(Ptr<Socket> socket);
	void SendIpv4Packets(Ptr<Packet>);
	void CheckRouteForRequest();

	void HandleConnect (Ptr<Socket> socket);
	void HandleAccept (Ptr<Socket> s, const Address &from);

	void SetDefense(int b, double c){
		m_defense = b;
		m_ratio = c;
	}

   double ChooseUniformRandomValue(double min, double max);
   list<MacCentredRoutingProtocol::Route*> GetRouteEntries();
	MacCentredRoutingProtocol::Route* GetRouteEntry();

private:
	Callback<void, double, Ptr<const Packet>, Ptr<Node> >  m_tracerxdata;         
	Ptr<Node> m_node;
	Ptr<NetDevice> m_device;
	Ptr<NetDevice> m_p2p_device;
	Address m_address;
	Address m_broadcast;
	Address m_sink_address;
	Address m_null_address;

	Address m_peer_address;
	Address m_mine_address;
	uint16_t m_pport;
	Ipv4Address m_peer_ipv4addr;
	Ipv4Address m_mine_ipv4addr;
	Ptr<OutputStreamWrapper> m_malicious_rxstream;
	uint32_t m_rx_packets;
	double m_rx_delay;
	double m_tx_time;
	McrpCache* m_malicious_mcrpcaches; 
	void MaliciousRecvPacket(double now, Ptr<Packet> pkt, Ptr<Node> node);

	Vector m_position;
	int m_previous_hops;
	list<MacCentredRoutingProtocol::Route*> *m_routes;
	Ptr<RandomVariableStream> m_random;
	Ptr<UniformRandomVariable> m_uni_random;
	Ptr<ExponentialRandomVariable> m_exp_random;
	bool m_is_running;
	uint32_t m_rx_pkts;
	uint32_t m_rx_bytes;

	int m_defense;
	double m_ratio;
};

#endif
