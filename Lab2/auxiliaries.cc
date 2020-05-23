
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "auxiliaries.h"

NS_LOG_COMPONENT_DEFINE("SimuAuxiliaries");

void PlaceInRectangle(NodeContainer nodelist, double X, double Y){
   Ptr<UniformRandomVariable> urX = NULL;
   urX = CreateObject<UniformRandomVariable>(); 
   urX->SetAttribute("Min", DoubleValue(0.00));
   urX->SetAttribute("Max", DoubleValue(1000.00));

   Ptr<UniformRandomVariable> urY = NULL;
   urY = CreateObject<UniformRandomVariable>(); 
   urY->SetAttribute("Min", DoubleValue(0.00));
   urY->SetAttribute("Max", DoubleValue(1000.00));

   Ptr<RandomRectanglePositionAllocator> positions = NULL;
   positions = CreateObject<RandomRectanglePositionAllocator>();

   positions->SetX(urX);
   positions->SetY(urY);

   MobilityHelper mobilityHelper;
   mobilityHelper.SetMobilityModel("ns3::ConstantPositionMobilityModel");
   mobilityHelper.SetPositionAllocator(positions); 
   mobilityHelper.Install(nodelist);

   ofstream output_stream("place_rectangle.csv", ios::trunc);
   for(uint32_t i=0; i<nodelist.GetN(); i++){
      Vector position = (nodelist.Get(i))->GetObject<MobilityModel>()->GetPosition();
      output_stream<<"Node"<<i<<","<<position.x<<","<<position.y<<endl;
      
   }
   output_stream.close();
}

void PlaceInCircle(NodeContainer nodelist, double X, double Y, double R){
   Ptr<UniformDiscPositionAllocator> positions = NULL;
   positions = CreateObject<UniformDiscPositionAllocator>();

   positions->SetRho(R);
   positions->SetX(X);
   positions->SetY(Y);

   MobilityHelper mobilityHelper;
   mobilityHelper.SetMobilityModel("ns3::ConstantPositionMobilityModel");
   mobilityHelper.SetPositionAllocator(positions); 
   mobilityHelper.Install(nodelist);

   ofstream output_stream("place_circle.csv", ios::trunc);
   for(uint32_t i=0; i<nodelist.GetN(); i++){
      Vector position = (nodelist.Get(i))->GetObject<MobilityModel>()->GetPosition();
      output_stream<<"Node"<<i<<","<<position.x<<","<<position.y<<","<<position.z<<endl;
   }
   output_stream.close();
}

void PlaceInRegular(NodeContainer nodelist, double gap){
   Ptr<ListPositionAllocator> positions = CreateObject<ListPositionAllocator> ();
   Ptr<UniformRandomVariable> uni_random = CreateObject<UniformRandomVariable>();
   positions->Add(Vector(0.00, 0.00, 0.00));
   uint32_t cnt = 0;
   for(uint32_t i=1; ; i++){
      uint32_t c = (i*2-1);
      uint32_t k = 0;
      //horizontal:
      for(uint32_t j=0; j<c/2 +1; j++){
         double X = uni_random->GetValue(j*gap +gap/3, (j+1)*gap);
         double Y = uni_random->GetValue((i-1)*gap +gap/3, (i)*gap);
         positions->Add(Vector(X, Y, 0.00));
         k = j;
      }

      //vertical:
      for(uint32_t j=0; j<c/2; j++){
         double X = uni_random->GetValue(k*gap +gap/3, (k+1)*gap);
         double Y = uni_random->GetValue(j*gap +gap/3, (j+1)*gap);
         positions->Add(Vector(X, Y, 0.00));
      }
      cnt += c;
      if(cnt>=nodelist.GetN()){
         break;
      }
  }

   MobilityHelper mobilityHelper;
   mobilityHelper.SetMobilityModel("ns3::ConstantPositionMobilityModel");
   mobilityHelper.SetPositionAllocator(positions); 
   mobilityHelper.Install(nodelist);

   ofstream output_stream("place_regular.csv", ios::trunc);
   for(uint32_t i=0; i<nodelist.GetN(); i++){
      Vector position = (nodelist.Get(i))->GetObject<MobilityModel>()->GetPosition();
      output_stream<<"Node"<<i<<","<<position.x<<","<<position.y<<","<<position.z<<endl;
   }
   output_stream.close();
}

void PrintNodes(NodeContainer nodelist){
   NS_LOG_FUNCTION_NOARGS();
   NS_LOG_UNCOND("----------------------------------------");
   for(uint32_t i=0; i<nodelist.GetN(); i++)
      PrintNodeInfo(nodelist.Get(i)); 
}

Ptr<Node> CreateNode(string name){ 
   Ptr<Node> node = CreateObject<Node>();  
   Names::Add(name, node);
   return node;
}

Ptr<Node> FindNode(string name){
   return Names::Find<Node>(name);//std::string("SINK"));
}

string GetNodeName(Ptr<Node> node){
   return Names::FindName(node);
}

bool IsSinkNode(Ptr<Node> node){ 
   string n = GetNodeName(node);
   return n=="SINK"?true:false;
}

string GetPacketName(int type){
   string names[9] = {"Data", "Hello", "Byebye", "Request", "Response", "Confirm", "Route", "Warning", "Unknown"};
   return names[type];
}

void PrintNodeInfo(Ptr<Node> node){
   Ptr<Ipv4> ipv4 = NULL;
   Ptr<Ipv6> ipv6 = NULL;
   uint32_t nodeId = node->GetId();
   uint32_t nDevices = node->GetNDevices();

   NS_LOG_UNCOND("## Node["<<nodeId<<"]: "<<GetNodeName(node));
   NS_LOG_UNCOND("Device#, "<<"MAC Address, "<<"Interface#, "<<"Seq#, "<<"IP Address");

   ipv4 = node->GetObject<Ipv4>();
   ipv6 = node->GetObject<Ipv6>();
   ipv6 = NULL;

   for (uint32_t i=0; i<nDevices; i++) {
      Ptr<NetDevice> dev = node->GetDevice(i);
      uint32_t nAddresses = 0;
      int32_t k = -1;

      if(ipv6) {k = ipv6->GetInterfaceForDevice(dev);}
      else if(ipv4){k = ipv4->GetInterfaceForDevice(dev);}/*ipv4*/ 

      if(k==-1){
         NS_LOG_UNCOND("  Device"<<int(i)<<", "<<dev->GetAddress()<<", ");
         continue;
      }

      if(ipv6) nAddresses = ipv6->GetNAddresses(k);
      else nAddresses = ipv4->GetNAddresses(k);

      for(uint32_t j=0; j<nAddresses; j++){
         if(ipv6){
            NS_LOG_UNCOND("  Device"<<int(i)<<", "<<
                           dev->GetAddress()<<", "<<
                           "  Interface"<<int(k)<<", "<<
                           "No."<<int(j)<<", "<<
                           ipv6->GetAddress(k,j).GetAddress()<<", ");//address,scope,......
         }
         else{
            NS_LOG_UNCOND("  Device"<<int(i)<<", "<<
                           dev->GetAddress()<<", "<<
                           "  Interface"<<int(k)<<", "<<
                        "No."<<int(j)<<", "<<
                        ipv4->GetAddress(k,j).GetLocal());//local,mask,broadcast,scope,second
         }
      }
   }
}

Ipv6Address GetIpv6LocalAddress(Ptr<Node> node){
   return ((node->GetObject<Ipv6>())->GetAddress(1, 0)).GetAddress();
}

Ipv6Address GetIpv6GlobalAddress(Ptr<Node> node){
   return ((node->GetObject<Ipv6>())->GetAddress(1, 1)).GetAddress();
}

Ipv4Address GetIpv4GlobalAddress(Ptr<Node> node){
   return ((node->GetObject<Ipv4>())->GetAddress(1, 0)).GetLocal();
}

string GetIpv4AddressString(Ipv4Address addr){
   string output="";
   std::ostringstream ossIpv4Addr;
   ossIpv4Addr << addr;
   output = ossIpv4Addr.str();//.c_str();
   return output;
}

int64_t GetMicroSeconds(Time t){
   return t.GetMicroSeconds();
}

Ptr<SensorNetDevice> GetSensorNetDevice(Ptr<Node> node){
   return DynamicCast<SensorNetDevice>(node->GetDevice(0));
}

Ptr<LrWpanNetDevice> GetLrWpanNetDevice(Ptr<Node> node){
   return DynamicCast<LrWpanNetDevice>(node->GetDevice(0));
}

Ptr<SixLowPanNetDevice> GetSixLowPanNetDevice(Ptr<Node> node){
   return DynamicCast<SixLowPanNetDevice>(node->GetDevice(1));
}

string GetRoutingName(int policy){
   return m_routing_name[policy];
}

int GetRoutingIdx(string name){
   for(int i=0; i<16; i++){
      if(name.compare(m_routing_name[i]) == 0)
         return i;
   }
   return -1;
}

string TrimHead(const string& s, const string& delimiters) {
   return s.substr(s.find_first_not_of(delimiters));
}

string TrimTail(const string& s, const string& delimiters) {
   return s.substr(0, s.find_last_not_of(delimiters));
}

string TrimEnds(const string& s, const string& delimiters) {
   return TrimHead(TrimTail(s,delimiters ),delimiters);
}


double ConvertDbmToW(double vDbm){
   double mW = std::pow (10.0, vDbm / 10.0);
   return mW / 1000.0;
}

