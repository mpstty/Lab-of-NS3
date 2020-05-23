#include "auxiliaries.h"
#include "lrwpanbase.h"

NS_LOG_COMPONENT_DEFINE("LrWpanTestBox");

LrWpanTestBox::LrWpanTestBox(){
   m_tx_packets = 0;
   m_rx_packets = 0;
   m_tx_delay = 0.00;
   m_rx_delay = 0.00;
   m_pin_one = 0;
   m_pin_two = 0;
}

LrWpanTestBox::LrWpanTestBox(double mean,
                         double distance,
                         uint32_t sensors,
                         double txpower,
                         int routing,
                         double duration )
   :m_lrwpan_helper(false){

   NS_LOG_FUNCTION_NOARGS();
   m_pin_one = 0;
   m_pin_two = 0;
   m_tx_packets = 0;
   m_rx_packets = 0;
   m_tx_delay = 0.00;
   m_rx_delay = 0.00;

   m_duration = duration;
   m_int_mean = mean;
   m_exp_random = CreateObject<ExponentialRandomVariable>();
   m_exp_random->SetAttribute("Mean", DoubleValue(m_int_mean));

   m_per_distance = distance;
   m_sensors = sensors;
   m_tx_power = txpower;
   m_routing = (E_ROUTE_POLICY)routing;

   m_last_energy_time = 0.00;
   m_last_energy_amount = 0.00;

   m_mcrplist = new vector<MacCentredRoutingProtocol*>();
   m_mcrplist->clear();
   m_mcrpcaches = new McrpCache();

	m_defense = 0;
	m_ratio = 0.00;
}

LrWpanTestBox::~LrWpanTestBox(){
   NS_LOG_FUNCTION("Destroyed");
   delete m_mcrpcaches;

   vector<MacCentredRoutingProtocol*>::iterator it;
   for(it=m_mcrplist->begin(); it!=m_mcrplist->end(); it++){
      delete (*it);
   }
   m_mcrplist->clear();
   delete m_mcrplist;
}

bool LrWpanTestBox::TestReceiver(Ptr<NetDevice> dev, Ptr<const Packet> pkt, uint16_t pcl, const Address& src) {
   NS_LOG_FUNCTION("Forward To Upper Layer");
   Ptr<Packet> p = pkt->Copy();
   
   dev->Send(p, dev->GetAddress(), Ipv6L3Protocol::PROT_NUMBER);
   return false;
}

void LrWpanTestBox::SetTraceFiles(string txname, string rxname){
   NS_LOG_FUNCTION("TX "<<txname<<"RX "<<rxname);
   m_txstream = Create<OutputStreamWrapper>(txname, ios::out);
   std::ostream* txos = m_txstream->GetStream();
   *txos<<"Sequence,"<<"Source,"<<"Time,"<<"Length"<<std::endl;

   m_rxstream = Create<OutputStreamWrapper>(rxname, ios::out);
   std::ostream* rxos = m_rxstream->GetStream();
   *rxos<<"RxNo,"<<"Sequence,"<<"Source,"<<"Length,"
         <<"TxTime,"<<"RxTime,"<<"Delay"<<std::endl;
   return;
}

void LrWpanTestBox::CreateNodes(){//uint32_t size){
   NS_LOG_FUNCTION("## Totally To Create '"<<m_sensors+1<<"' Nodes");

   m_all_nodes.Create(m_sensors + 1);

   Ptr<Node> node = m_all_nodes.Get(0);
   Names::Add("SINK", node);

   m_sink_nodes.Add(node);

   char buffer[16];
   for(uint32_t i=1; i<m_all_nodes.GetN(); i++){
      node = m_all_nodes.Get(i);
      memset(buffer, 0x00, sizeof(buffer));
      sprintf(buffer, "SENSOR#%03d", i);
      Names::Add(string(buffer), node);
   }
}

void LrWpanTestBox::SetMaliciousNodes(uint32_t left, uint32_t right, int defense, double ratio){
   m_pin_one = left;
   m_pin_two = right;
   m_defense = defense;
   m_ratio = ratio;
}

void LrWpanTestBox::LinkMaliciousNodes(){
   if(m_pin_one == 0 && m_pin_two == 0) return;

   NS_LOG_FUNCTION("Nodes"<<m_pin_one<<m_pin_two<<" to be tunnelled up");
   NS_ASSERT_MSG(m_all_nodes.GetN()>0, "No Existing Nodes");
   NS_ASSERT_MSG(m_pin_one>0 && m_pin_two>0 && m_pin_one!=m_pin_two, 
                                    "Invalid Malicious Nodes");
   m_pin_nodes = NodeContainer(m_all_nodes.Get(m_pin_one), m_all_nodes.Get(m_pin_two));
   
   string phyMode("DsssRate11Mbps");
   WifiHelper wifiHelper;
   wifiHelper.SetStandard(WIFI_PHY_STANDARD_80211b);
   wifiHelper.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                       "DataMode",StringValue (phyMode),
                                       "ControlMode",StringValue (phyMode));

   YansWifiChannelHelper wifiChannel;
   wifiChannel = YansWifiChannelHelper::Default();

   YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default();
   wifiPhy.SetChannel(wifiChannel.Create());
   wifiPhy.Set("TxPowerStart", DoubleValue (60.00));
   wifiPhy.Set("TxPowerEnd", DoubleValue (80.00));
   wifiPhy.Set("TxPowerLevels", UintegerValue(10));

   WifiMacHelper wifiMac;
   wifiMac.SetType("ns3::AdhocWifiMac");

   m_pin_devs = wifiHelper.Install(wifiPhy, wifiMac, m_pin_nodes);

   Ipv4StaticRoutingHelper routeHelper;
   InternetStackHelper istackHelper;
   istackHelper.SetRoutingHelper(routeHelper);
   istackHelper.Install(m_pin_nodes);

   Ipv4AddressHelper ipv4addrHelper;
   ipv4addrHelper.SetBase ("192.168.2.0", "255.255.255.0"); 
   Ipv4InterfaceContainer m_pin_ifxs = ipv4addrHelper.Assign(m_pin_devs);
   Ipv4GlobalRoutingHelper::PopulateRoutingTables();

   MacCentredRoutingProtocol *mcrp_one = NULL, *mcrp_two = NULL;

   mcrp_one = m_mcrplist->at(m_pin_one);
   mcrp_two = m_mcrplist->at(m_pin_two);

   mcrp_one->SetMaliciousPeer((m_pin_devs.Get(1))->GetAddress());
   mcrp_two->SetMaliciousPeer((m_pin_devs.Get(0))->GetAddress());
   mcrp_one->SetPeerIpv4Address(m_pin_ifxs.GetAddress(1, 0));
   mcrp_two->SetPeerIpv4Address(m_pin_ifxs.GetAddress(0, 0));
}

void LrWpanTestBox::PlaceNodes(){
   NS_LOG_FUNCTION_NOARGS();
   PlaceInRegular(m_all_nodes, m_per_distance);
}

void LrWpanTestBox::CreateNetDevices(){
   switch(m_routing){
      case ROUTE_MCRP:
         CreateMcrpNetDevices();
         break;
      default:
         break;
   }
}

void LrWpanTestBox::CreateMcrpNetDevices(){
   NS_LOG_FUNCTION_NOARGS();
   LrWpanSpectrumValueHelper spectrumVal;
   uint32_t channelId = 11;
      
   m_lrwpan_devs = m_lrwpan_helper.Install(m_all_nodes);

   m_lrwpan_helper.AssociateToPan(m_lrwpan_devs, 123);

   Ptr<SpectrumValue> psd1, psd2;//, psd0;

      //m_tx_power = 30.00;
   psd1 = spectrumVal.CreateTxPowerSpectralDensity(m_tx_power, channelId);
   Ptr<LrWpanNetDevice> sinkDev = DynamicCast<LrWpanNetDevice>(m_lrwpan_devs.Get(0));
   sinkDev->GetPhy()->SetTxPowerSpectralDensity(psd1); 

   psd2 = spectrumVal.CreateTxPowerSpectralDensity(m_tx_power, channelId);
   for(uint32_t i=1; i<m_lrwpan_devs.GetN(); i++){
      Ptr<LrWpanNetDevice> dev = DynamicCast<LrWpanNetDevice>(m_lrwpan_devs.Get(i));
      dev->GetPhy()->SetTxPowerSpectralDensity(psd2); 
   }

   string txFile = "send_mcrp.csv";
   string rxFile = "recv_mcrp.csv";
   MacCentredRoutingProtocol* routing = NULL;
   Ptr<OutputStreamWrapper> routestream = Create<OutputStreamWrapper>("table_mcrp.route", ios::out);
   LogComponentEnable("MacCentredRoutingProtocol", LOG_LEVEL_ALL);
   SetTraceFiles(txFile, rxFile);

   for(uint32_t i=0; i<m_lrwpan_devs.GetN(); i++){
      Ptr<LrWpanNetDevice> dev = DynamicCast<LrWpanNetDevice>(m_lrwpan_devs.Get(i));
      routing = new MacCentredRoutingProtocol(dev);
         routing->SetDefense(m_defense, m_ratio);
      routing->PrintRouteTable(routestream);
      m_mcrplist->push_back(routing);
   }
}

Ipv6RoutingHelper* LrWpanTestBox::GetIpv6RoutingHelper(){
   NS_LOG_FUNCTION_NOARGS();
   Ipv6RoutingHelper* routeHelper = nullptr;
   string routePolicy = "";
   string routeLog = "";
   switch(m_routing){
      case ROUTE_STATIC6:
         routeLog = "Ipv6StaticRouting";
         routeHelper = new Ipv6StaticRoutingHelper();
         break;
      default:
         NS_ASSERT_MSG(false, "Invalid Routing Protocol For Ipv6");
         break;
   }
   if(routeHelper){
      string rtFile = "table_" + routePolicy + ".route";
      routeHelper->PrintRoutingTableAllEvery(Seconds(3.0),
                                             Create<OutputStreamWrapper>(rtFile,
                                                                           std::ios::out));
      LogComponentEnable(routeLog.c_str(), LOG_LEVEL_ALL);
   }

   string rxFile = "recv_" + routePolicy + ".csv";
   string txFile = "send_" + routePolicy + ".csv";
   SetTraceFiles(txFile, rxFile);

   return routeHelper;     
}

void LrWpanTestBox::CreateInterfaces(){
   if(m_routing == ROUTE_MCRP){
      NS_LOG_FUNCTION(GetRoutingName(m_routing)<<"Routing Policy Not For Internet");
      return;
   }
   NS_LOG_FUNCTION_NOARGS();

   m_sixlowpan_helper.SetDeviceAttribute("ForceEtherType", BooleanValue(false));
   m_sixlowpan_helper.SetDeviceAttribute("Rfc6282", BooleanValue(false));//default: true
   m_sixlowpan_devs = m_sixlowpan_helper.Install(m_lrwpan_devs);

   InternetStackHelper istackHelper;
   Ipv6RoutingHelper* routeHelper = GetIpv6RoutingHelper(); //nullptr;
   istackHelper.SetRoutingHelper(*routeHelper);
      
   istackHelper.SetIpv4StackInstall(false);
   istackHelper.Install(m_all_nodes);

   Ipv6AddressHelper ipv6addrHelper;
   ipv6addrHelper.SetBase(Ipv6Address("2001:1::"), Ipv6Prefix(64));
   m_all_ifxs = ipv6addrHelper.Assign(m_sixlowpan_devs);//install interface 1
}

void LrWpanTestBox::CreateApplications(){
   double now = Simulator::Now().GetSeconds();
   switch(m_routing){
      case ROUTE_MCRP:
         CreateMcrpApplications(now);
         break;
      default:
         CreateSixLowPanApplications(now);
         break;
   }
}

void LrWpanTestBox::CreateMcrpApplications(double now){
   NS_LOG_FUNCTION(now);
   double delay = 0.00;
   Address dst = GetLrWpanNetDevice(m_all_nodes.Get(0))->GetAddress();

   for(vector<MacCentredRoutingProtocol*>::iterator it=m_mcrplist->begin(); 
                        it!=m_mcrplist->end(); it++){
      Ptr<Node> node = (*it)->GetNode();
      if(IsSinkNode(node)){
         McrpRecvPackets(*it);
         continue;
      }
      Simulator::Schedule(Seconds(delay), &LrWpanTestBox::McrpSendPackets, this, *it, dst);
   }
   return;
}

void LrWpanTestBox::McrpRecvPackets(MacCentredRoutingProtocol* route){
   NS_LOG_FUNCTION("UnDone");
   route->SetRxDataTrace(MakeCallback(&LrWpanTestBox::ParseRecvPacket, this));
}

void LrWpanTestBox::McrpSendPackets(MacCentredRoutingProtocol* route, Address dst){
   NS_LOG_FUNCTION_NOARGS();
   Ptr<Node> node = route->GetNode();
   if(IsSinkNode(node)){
      NS_LOG_FUNCTION("Controller/Sink cannot send Data!");
      return; 
   }

   double now = Simulator::Now().GetSeconds();	
   NS_LOG_FUNCTION(GetNodeName(node)<<"Time"<<now);
   Ptr<Packet> pkt = CreateSendPacket(now, node, 60);
   if(route->Transmit(now, pkt, dst, false) == -1){
      NS_LOG_FUNCTION("#Error#, Unable to Send! //TODO: Save to Cache");
   }
   double delay = m_exp_random->GetValue();
   Simulator::Schedule(Seconds(delay), &LrWpanTestBox::McrpSendPackets, this, route, dst);
}

void LrWpanTestBox::CreateSixLowPanApplications(double now){
   NS_LOG_FUNCTION_NOARGS();
   m_port = 9;
   TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
   Ptr<Node> sinkNode = m_all_nodes.Get(0);
   Ipv6Address sinkIpv6Addr = GetIpv6GlobalAddress(sinkNode);
   Ptr<Socket> sinkSocket = Socket::CreateSocket(sinkNode, tid);
   Inet6SocketAddress sinkLocalAddr = Inet6SocketAddress(sinkIpv6Addr, m_port);
   sinkSocket->Bind(sinkLocalAddr);
   sinkSocket->BindToNetDevice(GetSixLowPanNetDevice(sinkNode));
   sinkSocket->SetRecvCallback(MakeCallback(&LrWpanTestBox::SixLowPanRecvPackets, this));
   sinkSocket->SetAllowBroadcast(true);

   for(uint32_t i=1; i<=m_sensors; i++){
      Ptr<Node> agentNode = m_all_nodes.Get(i);
      Ptr<Socket> agentSocket = Socket::CreateSocket(agentNode, tid);
      Ipv6Address dstAddr = sinkIpv6Addr;
      agentSocket->SetRecvPktInfo(true);
      agentSocket->SetIpv6RecvHopLimit(true);

      agentSocket->BindToNetDevice(GetSixLowPanNetDevice(agentNode));
      agentSocket->SetAllowBroadcast(true);//false
      double delay = 0.00;
      Simulator::ScheduleWithContext(agentNode->GetId(), Seconds(delay),
                                       &LrWpanTestBox::SixLowPanSendPackets, this, 
                                       agentSocket, dstAddr, m_port);
   }
}

void LrWpanTestBox::SixLowPanRecvPackets(Ptr<Socket> socket){
   double now = Simulator::Now().GetSeconds();
   Ptr<Packet> packet = NULL;
   Ptr<Node> node = socket->GetNode();
   Ptr<NetDevice> dev = socket->GetBoundNetDevice();
   Ipv6Address rxAddr = GetIpv6GlobalAddress(node);

   NS_LOG_FUNCTION(now<<rxAddr);
   Address src;
   while((packet = socket->RecvFrom(src))) {
      ParseRecvPacket(now, packet, node);
      Inet6SocketAddress iSrc = Inet6SocketAddress::ConvertFrom(src);
      Ipv6Address txAddr = iSrc.GetIpv6();
      NS_LOG_FUNCTION(GetNodeName(node)<<"Time"<<now<<
                                       "Length"<<packet->GetSize()<<
                                       "from"<<src<<txAddr<<m_rx_packets<<
                                       "to"<<dev->GetAddress()<<rxAddr);
   }
}

void LrWpanTestBox::SixLowPanSendPackets(Ptr<Socket> socket, Ipv6Address dst, uint16_t port){
   Ptr<Node> node = socket->GetNode();
   double now = Simulator::Now().GetSeconds();	

   Ptr<Packet> pkt = CreateSendPacket(now, node, 60);
   Ipv6Address src = GetIpv6GlobalAddress(node);
   NS_LOG_FUNCTION(GetNodeName(node)<<"Time"<<now<<
                                       "Length"<<pkt->GetSize()<<
                                       "from"<<src<<"to"<<dst);

   Ptr<NetDevice> dev = socket->GetBoundNetDevice();
   Inet6SocketAddress sinkRemoteAddr = Inet6SocketAddress(dst, port);
   socket->Connect(sinkRemoteAddr);
   if(socket->Send(pkt) == -1){
      NS_LOG_FUNCTION(GetNodeName(node)<<"Time"<<now<<
                            "#Error#, Unable to Send! //TODO: Save to Cache");
   }
   double delay = m_exp_random->GetValue();
   Simulator::Schedule(Seconds(delay), &LrWpanTestBox::SixLowPanSendPackets, this, 
                                             socket, dst, port);
   return;
}

Ptr<Packet> LrWpanTestBox::CreateSendPacket(double now, Ptr<Node> node, uint32_t size){
   Address src = node->GetDevice(0)->GetAddress();
   m_tx_packets ++;

   int txSeq = m_tx_packets%8191;
   NS_LOG_FUNCTION("SEQ"<<txSeq<<"Time"<<now<<"Node"<<node->GetId()<<"Address"<<src);

   Ptr<Packet> pkt = Create<Packet>(size);

   McrpPktTag tag;
   tag.SetPktType(0);
   tag.SetPktTime(now);
   tag.SetPktSeq(txSeq);
   tag.SetPktAddress(node->GetDevice(0)->GetAddress());
   pkt->AddPacketTag(tag);
      
   uint32_t length = pkt->GetSize();
   std::ostringstream msgos;
   msgos<<txSeq<<","<<src<<","<<now<<","<<length;
   std::ostream* os = m_txstream->GetStream();
   *os<<msgos.str();
   *os<<std::endl;
	
   return pkt;
}

void LrWpanTestBox::ParseRecvPacket(double now, Ptr<const Packet> pkt, Ptr<Node> node){
   bool ret = false;
   McrpPktTag tag;
   pkt->PeekPacketTag(tag);
   ret = m_mcrpcaches->Insert(tag.GetPktSeq(), 
                                 tag.GetPktTime(), 
                                 tag.GetPktAddress(), 
                                    pkt, now);
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
      std::ostream* os = m_rxstream->GetStream();
      *os<<msgos.str()<<std::endl;
   }
}

void LrWpanTestBox::SetupEnergy(){
   NS_LOG_FUNCTION_NOARGS();

   LrWpanEnergySourceHelper lrwpanEnergySource;

   EnergySourceContainer energySources = lrwpanEnergySource.Install(m_all_nodes);

   DeviceEnergyModelContainer m_device_energy_models;
   SensorRadioEnergyModelHelper sensorRadioEnergyHelper;
   m_device_energy_models.Add(sensorRadioEnergyHelper.Install(m_lrwpan_devs, energySources));

  if(m_pin_nodes.GetN()==2){
      WifiRadioEnergyModelHelper  wifiRadioEnergyHelper;
      double voltage = 3.0;
      double idleCurrent = 0.273;
      double txCurrent = 0.380;
      double txPowerStart = 20.00;

      wifiRadioEnergyHelper.Set ("IdleCurrentA", DoubleValue (idleCurrent));
      wifiRadioEnergyHelper.Set ("TxCurrentA", DoubleValue (txCurrent));

      double eta = ConvertDbmToW (txPowerStart) / ((txCurrent - idleCurrent) * voltage);

      NS_LOG_FUNCTION("EEEEEEEEEEEEEEE"<<eta);

      wifiRadioEnergyHelper.SetTxCurrentModel("ns3::LinearWifiTxCurrentModel",
                                        "Voltage", DoubleValue (voltage),
                                        "IdleCurrent", DoubleValue (idleCurrent),
                                        "Eta", DoubleValue (eta));

      Ptr<DeviceEnergyModel> wifiEnergyModel;
      Ptr<WifiNetDevice> wifiNetDevice;
      uint32_t wifiNodeId;

      wifiNetDevice = (m_pin_devs.Get(0))->GetObject<WifiNetDevice> ();
      wifiNodeId = (m_pin_nodes.Get(0))->GetId();
      wifiRadioEnergyHelper.Install(wifiNetDevice, energySources.Get(wifiNodeId));
      m_device_energy_models.Add(wifiRadioEnergyHelper.Install(wifiNetDevice, energySources.Get(wifiNodeId)));

      wifiNetDevice = (m_pin_devs.Get(1))->GetObject<WifiNetDevice> ();
      wifiNodeId = (m_pin_nodes.Get(1))->GetId();
      m_device_energy_models.Add(wifiRadioEnergyHelper.Install(wifiNetDevice, energySources.Get(wifiNodeId)));
}

   string fullName = "";
   string shortName = "";
   shortName = GetRoutingName(m_routing); 
   fullName = "energy-detail-"+shortName+".csv";
   Ptr<OutputStreamWrapper> energyDetails = Create<OutputStreamWrapper>(fullName, ios::out);
   ostream* osa = energyDetails->GetStream();
   *osa<<"Time,"<<"NodeId,"<<"Current,"<<"Total"<<std::endl;

   fullName = "energy-average-"+shortName+".csv";
   Ptr<OutputStreamWrapper> averageStream = Create<OutputStreamWrapper>(fullName, ios::out);
   ostream* osb = averageStream->GetStream();
   *osb<<"Time,"<<"Average"<<std::endl;
   Simulator::Schedule(Seconds(1.0), &LrWpanTestBox::GetTotalEnergyConsumption, this, averageStream, m_device_energy_models);
      
      fullName = "rtt-"+shortName+".csv";
   Ptr<OutputStreamWrapper> rttStream = Create<OutputStreamWrapper>(fullName, ios::out);
      fullName = "rtt-"+shortName+"_average.csv";
   Ptr<OutputStreamWrapper> rttAvgStream = Create<OutputStreamWrapper>(fullName, ios::out);
   Simulator::Schedule(Seconds(m_duration), &LrWpanTestBox::GetMcrpRtts, this, rttStream, rttAvgStream);

   fullName = "final-"+shortName+".txt";
   Ptr<OutputStreamWrapper> resultStream = Create<OutputStreamWrapper>(fullName, ios::out);
   Simulator::Schedule(Seconds(m_duration), &LrWpanTestBox::GetFinalResult, this, resultStream);//, deviceEnergyModels);
   return;
}

void LrWpanTestBox::TraceRemainingEnergy(Ptr<Node> node, double oldval, double eng){	
	//NS_LOG_FUNCTION(Simulator::Now().GetSeconds()<<"Node"<<node->GetId()<< GetNodeName(node)<<"Remained"<<eng<<"Previous"<<oldval);
}

void LrWpanTestBox::TraceConsumedEnergy(Ptr<Node> node, Ptr<DeviceEnergyModel> model, Ptr<OutputStreamWrapper> stream, double oldval, double eng){
	//NS_LOG_FUNCTION(Simulator::Now().GetSeconds()<<"Node"<<node->GetId()<< GetNodeName(node)<<"Consumed"<<eng<<"Previous"<<oldval);
}

void LrWpanTestBox::GetTotalEnergyConsumption(Ptr<OutputStreamWrapper> stream, DeviceEnergyModelContainer& models){
   NS_LOG_FUNCTION_NOARGS();
   double now = Simulator::Now().GetSeconds();
   double totalEnergyConsumption = 0.00;
   uint32_t start = 1;

   Ptr<UniformRandomVariable> uniRv = CreateObject<UniformRandomVariable> ();

   double average = totalEnergyConsumption / now;
   NS_LOG_FUNCTION("Time"<<now<<
                    "Last Amount"<<m_last_energy_amount<<
                    "Current Amount"<<totalEnergyConsumption<<
                    "Average"<<average);

   std::ostream* os = stream->GetStream();
   *os << now << ","<< average <<std::endl;

   m_last_energy_amount = totalEnergyConsumption;
   m_last_energy_time = now;

   double delayTime = 1.00;

   if(m_duration - now <= delayTime){
      delayTime = 0.90;
   }
   Simulator::Schedule(Seconds(delayTime),
                           &LrWpanTestBox::GetTotalEnergyConsumption, this, 
                           stream, models);
}

void LrWpanTestBox::GetMcrpRtts(Ptr<OutputStreamWrapper> stream, Ptr<OutputStreamWrapper> avgstream){
   if(m_routing != ROUTE_MCRP)return;

   int iSeq = 0;
   double iRtt = 0.00;
   double cRtt = 0.00;

   ostream* osr = stream->GetStream();
   *osr<<"Node,"<<"Distance,"<<"Hops,"<<"RoundTT_M,"<<"RoundTT_C,"<<"Ratio"<<std::endl;

   ostream* avgosr = avgstream->GetStream();
   *avgosr<<"Seq,"<<"Average_RTT,"<<"Average_C_RTT,"<<"Ratio,"<<"Hops,"<<"Total_RTT"<<std::endl;

   vector<MacCentredRoutingProtocol*>::iterator it;
   list<MacCentredRoutingProtocol::Route *>::iterator allit;
   for(it=m_mcrplist->begin(); it!=m_mcrplist->end(); it++){
      MacCentredRoutingProtocol::Route* iRoute = (*it)->GetRouteEntry();
      *osr<<(*it)->GetNode()->GetId()<<","<<iRoute->dist<<","<<iRoute->hops<<","
          <<iRoute->rtt<<","<<iRoute->calt<<","<<iRoute->ratio<<std::endl;

      list<MacCentredRoutingProtocol::Route*> allRoutes = (*it)->GetRouteEntries(); 
      for(allit = allRoutes.begin(); allit!=allRoutes.end(); allit++){
         iSeq ++;
         if((*allit)->hops > 0 ){
            iRtt = (*allit)->rtt / (*allit)->hops;
            cRtt = (*allit)->calt / (*allit)->hops;
         }
         else{
            iRtt = 0.00;
            cRtt = 0.00;
         }
         *avgosr<<iSeq<<","<<iRtt<<","<<cRtt<<","<<iRoute->ratio<<","<<(*allit)->hops<<","<<(*allit)->rtt<<std::endl;
      }
   }
}

void LrWpanTestBox::GetFinalResult(Ptr<OutputStreamWrapper> stream){
   double now = Simulator::Now().GetSeconds();

   NS_LOG_FUNCTION("Time"<<now<<
                     "Energy Consumed"<<m_last_energy_amount<<
                     "Sensors"<<m_sensors);

   double ratio = 1.00 - (double)m_rx_packets/m_tx_packets;

   std::ostream* os = stream->GetStream();
   *os<<"Nodes="<<m_sensors<<std::endl;
   *os<<"Duration="<<now<<std::endl;
   *os<<"Energy Consumption="<<m_last_energy_amount<<std::endl;
   *os<<"Packets Sent="<<m_tx_packets<<std::endl;
   *os<<"Packets Recv="<<m_rx_packets<<std::endl;
   *os<<"Packet Loss="<<m_tx_packets - m_rx_packets<<", Ratio="<<ratio<<std::endl;
   *os<<"Total Delay/Packets="<<m_rx_delay<<"/"<<m_rx_packets<<std::endl;
   if(m_rx_packets==0)
      *os<<"Average Delay="<<"infinite"<<std::endl;
   else
      *os<<"Average Delay="<<(m_rx_delay/(double)m_rx_packets)<<std::endl;

   return;
}

void LrWpanTestBox::Execution(){
   double now = Simulator::Now().GetSeconds();
   NS_LOG_FUNCTION(now);

   LogComponentEnable("McrpPacketTag", LOG_LEVEL_ALL);
   GlobalValue::Bind("ChecksumEnabled", BooleanValue (true));//true
   GlobalValue::Bind("SimulatorImplementationType",StringValue("ns3::RealtimeSimulatorImpl"));
   PacketMetadata::Enable ();
   Packet::EnablePrinting ();

   CreateNodes();
   PlaceNodes();
   CreateNetDevices();
   LinkMaliciousNodes();
   SetupEnergy();
   CreateInterfaces();
   PrintNodes(m_all_nodes);
   CreateApplications();

   Simulator::Stop(Seconds(m_duration));

   string animFile = "anim_"+ GetRoutingName(m_routing) + ".xml";
   AnimationInterface animIfx(animFile);
   animIfx.UpdateNodeDescription(m_all_nodes.Get(0), "SINK");
   animIfx.UpdateNodeColor(m_all_nodes.Get(0), 0, 255, 0);
   animIfx.EnablePacketMetadata();

   animFile = "anim-rt_"+ GetRoutingName(m_routing) + ".xml";
   animIfx.EnableIpv4RouteTracking (animFile, Seconds(0), Seconds(m_duration), Seconds(0.25));

   Simulator::Run();
   Simulator::Destroy();
}

