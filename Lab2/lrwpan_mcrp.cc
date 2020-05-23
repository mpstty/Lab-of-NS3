#include "auxiliaries.h"
#include "lrwpan_mcrp.h"
NS_LOG_COMPONENT_DEFINE("MacCentredRoutingProtocol");

MacCentredRoutingProtocol::MacCentredRoutingProtocol(Ptr<NetDevice> dev)
	: m_null_address(0, NULL, 0),
	  m_peer_address(0, NULL, 0),
	  m_mine_address(0, NULL, 0),
	  m_rx_pkts(0),
	  m_rx_bytes(0){

   m_previous_hops = 0;
   m_is_running = false;
   m_device = dev;
   m_node = m_device->GetNode();
   m_device->SetReceiveCallback(MakeCallback(&MacCentredRoutingProtocol::Receiver, this));
   m_position = m_node->GetObject<MobilityModel>()->GetPosition();
   m_address = m_device->GetAddress();
   m_broadcast = m_device->GetBroadcast();
   m_pport = 0;
   m_tx_time=-1;
   m_malicious_mcrpcaches = NULL;
	m_defense = 0;
	m_ratio = 0.00;
   m_exp_random = CreateObject<ExponentialRandomVariable>();
   m_exp_random->SetAttribute("Mean", DoubleValue(1.00));
   CreateRouteTable();
   StartZeroRoute(Simulator::Now().GetSeconds());
}

MacCentredRoutingProtocol::~MacCentredRoutingProtocol(){
   DeleteRouteTable();
   if (m_malicious_mcrpcaches) delete m_malicious_mcrpcaches;
}

void MacCentredRoutingProtocol::SetMaliciousPeer(Address peer){
   m_p2p_device = m_node->GetDevice(1);
   m_peer_address = peer; 
   m_mine_address = m_p2p_device->GetAddress();
}

void MacCentredRoutingProtocol::MaliciousRecvPacket(double now, Ptr<Packet> pkt, Ptr<Node> node){
   bool ret = false;
   McrpPktTag tag;
   pkt->PeekPacketTag(tag);
   ret = m_malicious_mcrpcaches->Insert(tag.GetPktSeq(), tag.GetPktTime(), 
                                          tag.GetPktAddress(), pkt, now);
   if(ret==true){
      uint32_t length = pkt->GetSize();
      double txTime = tag.GetPktTime();
      double rxTime = now;
      double delay = rxTime - txTime;
                    
      m_rx_packets++;
      m_rx_delay += delay;

      std::ostringstream msgos;
      msgos<<m_rx_packets<<","
            <<tag.GetPktSeq()<<","
            <<tag.GetPktAddress()<<","
            <<length<<","
            <<txTime<<","
            <<rxTime<<","
          <<delay;
      std::ostream* os = m_malicious_rxstream->GetStream();
      *os<<msgos.str()<<std::endl;
   }
}

void MacCentredRoutingProtocol::SetPeerIpv4Address(Ipv4Address peer){
   string rxname = "mal_recv_"+GetNodeName(m_node)+".csv";
   m_malicious_rxstream = Create<OutputStreamWrapper>(rxname, ios::out);

   m_rx_packets = 0.00;
   m_rx_delay = 0.00;
   m_malicious_mcrpcaches = new McrpCache();


   m_pport = 29;
   TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory"); 
   m_peer_ipv4addr = peer;
   m_mine_ipv4addr=m_node->GetObject<Ipv4L3Protocol>()->GetAddress(1, 0).GetLocal();

   NS_LOG_FUNCTION("CHECK"<<"MINE"<<m_peer_ipv4addr<<"PEER"<<m_mine_ipv4addr);
   Ptr<Socket> sinkSocket = Socket::CreateSocket(m_node, tid);
   InetSocketAddress sinkLocalAddr = InetSocketAddress(m_mine_ipv4addr, m_pport);
   sinkSocket->Bind(sinkLocalAddr); 

   sinkSocket->SetRecvCallback(MakeCallback(
            &MacCentredRoutingProtocol::RecvIpv4Packets, this));
}

void MacCentredRoutingProtocol::HandleAccept (Ptr<Socket> s, const Address &from){
   NS_LOG_INFO("Accept Input From " << InetSocketAddress::ConvertFrom(from).GetIpv4());
   s->SetRecvCallback(MakeCallback(&MacCentredRoutingProtocol::RecvIpv4Packets, this)); 
}

void MacCentredRoutingProtocol::SendIpv4Packets(Ptr<Packet> pkt){
   NS_LOG_FUNCTION("Time"<<Simulator::Now().GetSeconds()<<GetNodeName(m_node)<<
                     "Mine"<<m_mine_ipv4addr<<"Peer"<<m_peer_ipv4addr);

   TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
   Ptr<Socket> agentSocket = Socket::CreateSocket(m_node, tid);  
   InetSocketAddress sinkRemoteAddr = InetSocketAddress(m_peer_ipv4addr, m_pport);
   agentSocket->Connect(sinkRemoteAddr);
   if(agentSocket->Send(pkt)==-1){
      NS_LOG_FUNCTION("Unable to send! ");
   }
}

void MacCentredRoutingProtocol::HandleConnect (Ptr<Socket> socket){
   NS_LOG_FUNCTION("Connected to Peer");
}

double MacCentredRoutingProtocol::ChooseUniformRandomValue(double min, double max){
   static Ptr<UniformRandomVariable> vgurandom = CreateObject<UniformRandomVariable>();
   return vgurandom->GetValue(min, max);
}

void MacCentredRoutingProtocol::RecvIpv4Packets(Ptr<Socket> socket){
   double now = Simulator::Now().GetSeconds();
   Address srcAddr;
   Ptr<Packet> packet;
   while((packet = socket->RecvFrom(srcAddr))) { 
      Ipv4Address ipv4Src = (InetSocketAddress::ConvertFrom(srcAddr)).GetIpv4();
      McrpPktTag* tag = GetTagFromPacket(packet);
      int type = tag->GetPktType();
      NS_LOG_FUNCTION("Time"<<now<<"Type"<<GetPacketName(type)<<
                      GetNodeName(m_node)<<"From"<<ipv4Src<<
                      "Mine"<<m_mine_address<<"Peer"<<m_peer_address);
      NS_ASSERT_MSG(type==0 || type==2, "Invalid Packet Type");
      if(type==2){
         NS_LOG_FUNCTION("To Handle Response");
         Address dest = tag->GetPktAddress();
         Address next = m_peer_address;
         int hops = tag->GetPktHops()+1;
			double mRtt = (double)(hops+1) * ChooseUniformRandomValue(0.0042, 0.0050);
         if(m_previous_hops > hops || UpdateMaliciousRoute(dest, next, hops) == true){
            SendResponse(hops, mRtt);
         }
      }
      else{//type==0
         NS_LOG_FUNCTION("To Handle Data");
         MaliciousRecvPacket(now, packet, m_node);
      }
   }
}


void MacCentredRoutingProtocol::CreateRouteTable(){
   m_routes = new list<MacCentredRoutingProtocol::Route*>();
   m_routes->clear();
}

void MacCentredRoutingProtocol::DeleteRouteTable(){
   if(m_routes!=NULL){
      for(list<MacCentredRoutingProtocol::Route*>::iterator it=m_routes->begin(); 
                  it!=m_routes->end(); it++){
         delete (*it);
      }
      m_routes->clear();
      delete m_routes;
   }
}
void MacCentredRoutingProtocol::TxDataConfirmNotification(McpsDataConfirmParams params){
   NS_LOG_FUNCTION("MSDU = "<<int(params.m_msduHandle) <<
                    "LrWpanMcpsDataConfirmStatus = " << params.m_status);
}   

void MacCentredRoutingProtocol::SetRxDataTrace(Callback< void, double, Ptr<const Packet>, Ptr<Node> > rdcb){
   m_tracerxdata = rdcb;
}

void MacCentredRoutingProtocol::PrintRouteTable(Ptr<OutputStreamWrapper> stream){
   Simulator::Schedule(Seconds(3.0), &MacCentredRoutingProtocol::PrintRoutes, this, stream);
}

void MacCentredRoutingProtocol::PrintRoutes(Ptr<OutputStreamWrapper> stream){
   std::ostream* os = stream->GetStream();
   *os <<"#Mac Routing Table of "<<GetNodeName(m_node)<<" ("<<m_address<<")"
         <<", Time: "<<Now().As(Time::S)
         <<", Local time: "<< m_node->GetLocalTime().As(Time::S)
         <<std::endl;
      
   *os	<<"  "
         <<"No."					<<"    "
         <<"SOURCE"			<<"    "
         <<"DESTINATION"	<<"    "
         <<"NEXT(GW)"		<<"    "
         <<"HOPS"				<<"    "
         <<"FLAG"				<<"    "
         <<"Distance"		<<"    "
         <<"RTT_M(s)"		<<"    "
         <<"RTT_C(s)"		<<"    "
         <<"Ratio"				<<"    "
         <<std::endl;

   for(list<MacCentredRoutingProtocol::Route*>::iterator it=m_routes->begin(); 
              it!=m_routes->end(); it++){
      MacCentredRoutingProtocol::Route* route = (*it);
      if(Mac16Address::ConvertFrom(route->dest) != Mac16Address("02-02-00:01")){
         //NS_LOG_FUNCTION...
         continue;
      }
      *os	<<"  "
            <<route->seq 	<<"    "
            <<m_address  	<<"    "
            <<route->dest	<<"    "
            <<route->next	<<"    "
            <<route->hops	<<"    "
            <<route->flag	<<"    "
            <<route->dist	<<"    "
            <<route->rtt 	<<"    "
            <<route->calt <<"    "
            <<route->ratio<<"    "
				<<std::endl;
   }
   *os <<"\n\n\n";
   Simulator::Schedule(Seconds(3.0), &MacCentredRoutingProtocol::PrintRoutes, this, stream);
}

McrpPktTag* MacCentredRoutingProtocol::GetTagFromPacket(Ptr<const Packet> pkt){
   McrpPktTag *tag = new McrpPktTag();
   pkt->PeekPacketTag(*tag);
   return tag;
}

MacCentredRoutingProtocol::Route* MacCentredRoutingProtocol::GetRouteEntry(){
	double ortt = 10000000.00;
	MacCentredRoutingProtocol::Route* oroute = NULL;
   list<MacCentredRoutingProtocol::Route*>::iterator it;	
   for(it=m_routes->begin(); it!=m_routes->end(); it++){
      if( (*it)->dest == m_sink_address && (*it)->flag==1){
			if( (*it)->rtt < ortt ){
				ortt = (*it)->rtt;
				oroute = (*it);
			}
		}
	}
	return oroute;	
}

list<MacCentredRoutingProtocol::Route*> MacCentredRoutingProtocol::GetRouteEntries(){
   list<MacCentredRoutingProtocol::Route*> routeList;
   list<MacCentredRoutingProtocol::Route*>::iterator it;	
   for(it=m_routes->begin(); it!=m_routes->end(); it++){
      if( (*it)->dest == m_sink_address){
         routeList.push_back((*it));
		}
	}
	return routeList;	
}

void MacCentredRoutingProtocol::StartZeroRoute(double now){
   if(IsSinkNode(m_node)){
      NS_LOG_FUNCTION(GetNodeName(m_node)<<m_address<<"Create Generis Route");
      MacCentredRoutingProtocol::Route *route = NULL;
      m_sink_address = m_address;
      route = new MacCentredRoutingProtocol::Route();	
      route->hops = 0;
      route->seq = 1;
      route->dest = m_address;
      route->next = m_address;
         route->flag = 1;
         route->rtt = 0.00;
      m_routes->push_back(route);
   }
   return;
}

Address MacCentredRoutingProtocol::LookupMcrpRoute(Address& dest){
   NS_LOG_FUNCTION(GetNodeName(m_node)<<
                    "Time"<<Simulator::Now().GetSeconds()<<
                    "Destination"<<dest <<
										"Defense"<<m_defense);
   list<MacCentredRoutingProtocol::Route*>::iterator it;	
   Address nextAddr = m_null_address;
   int realHops = 0;
   double lastRatio = 0.00;
   Ptr<UniformRandomVariable> opt = CreateObject<UniformRandomVariable>();

   for(it=m_routes->begin(); it!=m_routes->end(); it++){
      if( (*it)->dest != dest ){
         continue;
      }

		if( m_peer_address != m_null_address && (*it)->next == m_peer_address && (*it)->flag==1 ){
			NS_LOG_FUNCTION("Found Peer Address"<<(*it)->next<<"to Destination"<<dest<<"Hops"<<(*it)->hops);
			return m_peer_address;
		}
		else{
			if(m_defense == 0){
				if((*it)->flag == 1 && (nextAddr == m_null_address || opt->GetValue(0.01, 1.00)>0.5)){
					nextAddr = (*it)->next;
					realHops = (*it)->hops;
					lastRatio = (*it)->ratio;
				}
			}
			else{//in defense 
				if(nextAddr == m_null_address){
					nextAddr = (*it)->next;
					realHops = (*it)->hops;
					lastRatio = (*it)->ratio;
					continue;
				}
				
				if((*it)->ratio > m_ratio){
					if(lastRatio < m_ratio || realHops > (*it)->hops ){
						nextAddr = (*it)->next;
						realHops = (*it)->hops;
						lastRatio = (*it)->ratio;
					}
				}
			}
		}
   }
   if(nextAddr == m_null_address){
      NS_LOG_FUNCTION("No Route to"<<dest);
   }
   else{
      NS_LOG_FUNCTION("via Next Address "<<nextAddr<<" to "<<dest<<"hops"<<realHops);
   }
   return nextAddr;
}

void MacCentredRoutingProtocol::SendRequest(double now){
   if(IsSinkNode(m_node)){//||IsCtrlNode(m_node)){
      NS_LOG_FUNCTION(m_address<<"Sink/Controller cannot send Hello/Request");
      return;
   }
   Time ct = Simulator::Now();
   NS_LOG_FUNCTION(GetNodeName(m_node)<<"Time"<<ct.GetSeconds());

   if(m_tx_time==-1.00)m_tx_time = ct.GetSeconds();

   McrpPktTag tag;
   tag.SetPktType(1);
   tag.SetPktAddress(m_address);
   Ptr<Packet> pkt = Create<Packet>(60);
   pkt->AddPacketTag(tag);
  
   Simulator::ScheduleNow(&NetDevice::Send, m_device, pkt, m_broadcast, 0);
   return;
}

void MacCentredRoutingProtocol::CheckRouteForRequest(){
   NS_LOG_FUNCTION(GetNodeName(m_node)<<"Time"<<Simulator::Now().GetSeconds());
   Address next = LookupMcrpRoute(m_sink_address);
   if(next == m_null_address){
      SendRequest(Simulator::Now().GetSeconds());
   }
}

int MacCentredRoutingProtocol::Transmit(double now, Ptr<Packet> pkt, Address dst, bool forward){
	double tNow = Simulator::Now().GetSeconds();
   NS_LOG_FUNCTION(GetNodeName(m_node)<<"Time"<<tNow<<"to"<<dst);
   Address next = LookupMcrpRoute(dst);
   if(next == m_null_address){
      if(IsBusy()==false){
         SetBusyFor(1.0);
         SendRequest(now);
         m_sink_address = dst;//mazw
      }
      NS_LOG_FUNCTION("No Route to"<<dst<<"Drop Packet");
      return -1;
   }
   if(next == m_peer_address){
      NS_LOG_FUNCTION("P2P Transmit Data");
		MaliciousRecvPacket(tNow, pkt, m_node);
      Simulator::ScheduleNow(&MacCentredRoutingProtocol::SendIpv4Packets, this, pkt);
   }
   else{
      NS_LOG_FUNCTION("LRWPAN Transmit Data");
      Simulator::ScheduleNow(&NetDevice::Send, m_device, pkt, next, 0);
   }
   return 0;
} 

bool MacCentredRoutingProtocol::Receiver(Ptr<NetDevice> dev, Ptr<const Packet> pkt, uint16_t pcl, const Address& src){

   NS_ASSERT_MSG(src!=m_address, "Receive My Own Packet??????");

   double now = Simulator::Now().GetSeconds();
   McrpPktTag* tag = GetTagFromPacket(pkt);
   int type = tag->GetPktType();
   NS_LOG_FUNCTION("Time"<<now<<GetNodeName(m_node)<<m_address <<"Type"<<GetPacketName(type));
   switch(type){
      case 0:
         ReceiveData(now, pkt, tag, src);
         break;
      case 1:
         ReceiveRequest(now, tag, src);
         break;
      case 2://Route
         ReceiveResponse(now, tag, src);
         break;
      default:
         NS_LOG_FUNCTION(this<<"Invalid Packet Type");
         break;
      }
   delete tag;
   return true;
}

void MacCentredRoutingProtocol::InsertRoute(Address dest, Address next, int hops, int flag){
   NS_LOG_FUNCTION(GetNodeName(m_node));
   MacCentredRoutingProtocol::Route* route = new MacCentredRoutingProtocol::Route();
   route->seq = m_routes->size()+1;
   route->hops = hops;
   route->mine = m_address;
   route->next = next;
   route->dest = dest;
   route->flag = flag;
   route->rtt = 0.00; 
   m_routes->push_back(route);
}

void MacCentredRoutingProtocol::ReceiveRequest(double now, McrpPktTag* tag, const Address& src){
   NS_LOG_FUNCTION(GetNodeName(m_node));
   Address dst = src;
   Address next = src;
   int hops = 1;
   InsertRoute(dst, next, hops, 1); //availd route: to neighbor
   SendResponse(0, 0.00);
   return;
}

void MacCentredRoutingProtocol::SendResponse(int hops, double rttime){
   double now=Simulator::Now().GetSeconds();
   NS_LOG_FUNCTION(now<<GetNodeName(m_node)<<"RTT"<<rttime);
   McrpPktTag tag;
   Ptr<Packet> pkt = NULL;
   if(hops == 0){
      for(list<MacCentredRoutingProtocol::Route*>::iterator it=m_routes->begin(); 
                  it!=m_routes->end(); it++){
         if((*it)->dest==m_sink_address){
            NS_LOG_FUNCTION("Beginning Route to Sink"<<"Hops"<<(*it)->hops);
            tag.SetPktType(2);	
            tag.SetPktHops((*it)->hops);	
            tag.SetPktAddress(m_sink_address);
            if(IsSinkNode(m_node)){
               tag.SetPktTime(now);
               tag.SetRttTime(rttime);
            }
            else{
               tag.SetPktTime(now);
               tag.SetRttTime((*it)->rtt);
            }

            pkt = Create<Packet>(60);
            pkt->AddPacketTag(tag);
            break;
         }
      }
   }
   else{
      NS_LOG_FUNCTION("Better Route to Sink"<<"Hops"<<hops);
      tag.SetPktType(2);	
      tag.SetPktHops(hops);
      tag.SetPktAddress(m_sink_address);
         tag.SetPktTime(now);
         tag.SetRttTime(rttime);
      pkt = Create<Packet>(60);
      pkt->AddPacketTag(tag);
   }

   if(pkt){
      Simulator::ScheduleNow(&NetDevice::Send, m_device, pkt, m_broadcast, 0);
   }
   return;
}

bool MacCentredRoutingProtocol::DeleteMaliciousRoute(Address dest, Address next, int hops){
   NS_LOG_FUNCTION(GetNodeName(m_node));
   bool found = false;
   bool remove = false;
   for(list<MacCentredRoutingProtocol::Route*>::iterator rt = m_routes->begin();rt!=m_routes->end();){
      if((*rt)->dest == m_sink_address){
         if((*rt)->next == next){
            found = true;
            if((*rt)->hops>hops){
               remove = true;
               NS_LOG_FUNCTION("Delete Old One, Add New One, Send New One");
               delete (*rt);
               rt = m_routes->erase(rt);
            }
         }
      }
      rt++;
   }
   return (found==false || remove==true)?true:false;
}

void MacCentredRoutingProtocol::ReceiveResponse(double now, McrpPktTag* tag, const Address& src){
   if(IsSinkNode(m_node)){
      NS_LOG_FUNCTION("Sink cannot Update Route via response");
      return;
   }
   NS_LOG_FUNCTION(GetNodeName(m_node)<<"Time"<<now<<"from"<<src<<"Receive Route");
   Address dest = tag->GetPktAddress();
   Address next = src;
   double txtime = tag->GetPktTime();
   double rttime = tag->GetRttTime();
   int hops = tag->GetPktHops()+1;
   bool ret = UpdateRoute(dest, next, hops, txtime, &rttime);
   if(ret==true){
      SendResponse(hops, rttime);
      if(m_peer_address != m_null_address &&
            DeleteMaliciousRoute(dest, m_peer_address, hops) == true){
         SendToPeer(hops);
      }
   }
}

void MacCentredRoutingProtocol::SendToPeer(int hops){
   m_previous_hops = hops;
   NS_LOG_FUNCTION("Send Response To Peer"<<m_peer_address<<"Hops"<<hops);
   McrpPktTag tag;
   Ptr<Packet> pkt = NULL;
   tag.SetPktType(2);	
   tag.SetPktHops(hops);
   tag.SetPktAddress(m_sink_address);
   pkt = Create<Packet>(60);
   pkt->AddPacketTag(tag);

   if(pkt){
      Simulator::ScheduleNow(&MacCentredRoutingProtocol::SendIpv4Packets, this, pkt);
   }
}

bool MacCentredRoutingProtocol::HasMcrpRoute(Address dest){
   NS_LOG_FUNCTION(GetNodeName(m_node));
   list<MacCentredRoutingProtocol::Route*>::iterator it;
   for(it=m_routes->begin(); it!=m_routes->end(); it++){
      if((*it)->dest==dest){
         return true;
      }
   }
   return false;
}

bool MacCentredRoutingProtocol::UpdateMaliciousRoute(Address dest, Address next, int hops){
   NS_LOG_FUNCTION(GetNodeName(m_node));
   MacCentredRoutingProtocol::Route *route = NULL;
   bool found = false;
   bool insert = false;
   for(list<MacCentredRoutingProtocol::Route*>::iterator rt = m_routes->begin();rt!=m_routes->end();){
      if((*rt)->dest == m_sink_address){
         if((*rt)->next == next){
            found = true;
            if((*rt)->hops>hops){
               insert = true;
               NS_LOG_FUNCTION("Delete Old One, Add New One, Send New One");
               delete (*rt);
               rt = m_routes->erase(rt);
            }
         }
      }
      rt++;
   }


   if((found==true && insert == true) || found == false){
      NS_LOG_FUNCTION("Insert New One, Send New One");
      route = new MacCentredRoutingProtocol::Route();
      route->seq = m_routes->size()+1;
      route->hops = hops;
      route->dest = dest;
      route->next = next;
         route->flag = 1;
         //route->rtt = Simulator::Now().GetSeconds();
         route->rtt = (double)(hops+1)*0.005;
		CalculateRtt(route);
      m_routes->push_back(route);
      return true;
   }
   return false;
}

void MacCentredRoutingProtocol::CalculateRtt(MacCentredRoutingProtocol::Route *route){ 
	double aDist = 100.00;
   double eTime = 0.0001; // 1/10000
   double dTime = 0.0019;
   double ioLen = 480.00;// 60x8
   double ioBw = 250000.00;
   double lSpeed = pow(10, 8) * 3.00;

   route->dist = sqrt(pow(m_position.x, 2) + pow(m_position.y, 2) );
   if(route->hops==0){
      route->calt = 0.00;
         route->ratio =1.00;
	}
   else{
		aDist = (route->dist)/(double)(route->hops);
      route->calt = (double)(route->hops) * (aDist/lSpeed + ioLen/ioBw + eTime) +  \
										route->dist/lSpeed + ioLen/ioBw + eTime + dTime;

      route->ratio = (route->calt)/(route->rtt);
	}
}

bool MacCentredRoutingProtocol::UpdateRoute(Address dest, Address next, int hops, double txtime, double *rttime){
   NS_LOG_FUNCTION(GetNodeName(m_node)<<"Tx Time"<<txtime<<(*rttime));
	Time ct = Simulator::Now();
	double rx_time_ns = ct.GetSeconds();
	double rt_time_ns = 0.00;

   MacCentredRoutingProtocol::Route *route = NULL;
   int better = 1;
	int flag = 1;
   for(list<MacCentredRoutingProtocol::Route*>::iterator rt = m_routes->begin();rt!=m_routes->end();){
      if((*rt)->dest == m_sink_address){
         NS_LOG_FUNCTION("Hops"<<(*rt)->hops<<"vs."<<hops);
         if((*rt)->hops > hops){
            NS_LOG_FUNCTION("Delete Old One, Add New One, Broadcast New One");
            (*rt)->flag = 2;
            better = 1;
            flag = 1;
         }
         else if((*rt)->hops == hops){
            NS_LOG_FUNCTION("Keep Old One, Add New One, Broadcast New One");
            better = 0;
				flag = (*rt)->flag;
         }
         else{
            NS_LOG_FUNCTION("Keep Old One, Drop New One");
            better = -1;
				flag = 2;
				break;
         }
      }
      rt++;
   }
	
	route = new MacCentredRoutingProtocol::Route();
   route->seq = m_routes->size()+1;
   route->hops = hops;
   route->dest = dest;
   route->next = next;
	route->flag = flag;
	rt_time_ns = rx_time_ns - txtime + (*rttime);
	if(m_mine_address == m_null_address && rx_time_ns - txtime > 0.005){
		rt_time_ns = 0.004 + (*rttime);
	}
	route->rtt = rt_time_ns;
	(*rttime) = route->rtt;
	CalculateRtt(route);
   m_routes->push_back(route);

   return better==1?true:false;
}

void MacCentredRoutingProtocol::SetIdle(){
   NS_LOG_FUNCTION(m_address<<"Time"<<Simulator::Now().GetSeconds()<<"Set Idle");
   m_is_running = false;
}

void MacCentredRoutingProtocol::SetBusyFor(double secs){
   m_is_running = true;
   NS_LOG_FUNCTION(m_address<<"Time"<<Simulator::Now().GetSeconds()<<"Set Busy for"<<secs);
   Simulator::Schedule(Seconds(secs), &MacCentredRoutingProtocol::SetIdle, this);
}

bool MacCentredRoutingProtocol::IsBusy(){
   return m_is_running;	
}

void MacCentredRoutingProtocol::ReceiveData(double now, Ptr<const Packet> pkt, McrpPktTag* tag, const Address& src){
   NS_LOG_FUNCTION(GetNodeName(m_node)<<"Time"<<now<<"from"<<src);
   if(m_node->GetId()==0){
      m_tracerxdata(now, pkt, m_node);
   }
   else{
      Ptr<Packet> txpkt = pkt->Copy();
      int ret = Transmit(now, txpkt, m_sink_address, true);
      if(ret == -1){
         NS_LOG_FUNCTION("Unable to Forward, No Route to "<<m_sink_address<<"Drop!");
      }
   }
   return ;
}
