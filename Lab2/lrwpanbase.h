#ifndef _WSN_MCRP_BASE_H
#define _WSN_MCRP_BASE_H

#include <iostream>
#include <iomanip>
#include <cmath>
#include <ctime>
#include <map>
#include <string>
#include <iterator>

#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/core-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/lr-wpan-module.h"
#include "ns3/sixlowpan-module.h"
#include "ns3/spectrum-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/energy-module.h"
#include "ns3/netanim-module.h"
#include "ns3/point-to-point-module.h"
//#include "ns3/leach-module.h"

//#include "wifibase.h"
#include "lrwpan_mcrp_tag.h"
#include "lrwpan_mcrp.h"
#include "auxiliaries.h"

using namespace ns3;
using namespace std;

class LrWpanTestBox{// : public WifiTestBox{
public:
   LrWpanTestBox();
   //LrWpanTestBox(string name,
   LrWpanTestBox(double mean,
               double distance,
               uint32_t sensors,
               double txpower,
               int routing,
               double duration );
   ~LrWpanTestBox();
   bool TestReceiver(Ptr<NetDevice> dev, Ptr<const Packet> pkt, uint16_t pcl, const Address& src);
   void CreateNodes();
   void PlaceNodes();
   void CreateNetDevices();// void SetupLrWpanLayer();
   void CreateMcrpNetDevices();// void SetupLrWpanLayer();
   void CreateLeachNetDevices();// void SetupLrWpanLayer();

   void CreateInterfaces();// void SetupInternetLayer();

   void CreateApplications();
   void CreateLeachApplications(double);
   void CreateMcrpApplications(double);
   void CreateSixLowPanApplications(double now);

   bool LeachRecvPackets(Ptr<NetDevice>, Ptr<const Packet> pkt, uint16_t pcl, const Address& src);
   void LeachSendPackets(Ptr<Node> node, Address dst);
   //void LeachSendPackets(Ptr<Node> node, Address dst, Ptr<Packet> packet);

   void McrpRecvPackets(MacCentredRoutingProtocol* route);
   void McrpSendPackets(MacCentredRoutingProtocol* route, Address dst);

   void SixLowPanRecvPackets(Ptr<Socket> socket);
   void SixLowPanSendPackets(Ptr<Socket> socket, Ipv6Address dst, uint16_t port);

   Ptr<Packet> CreateSendPacket(double now, Ptr<Node> node, uint32_t size);
   void ParseRecvPacket(double now, Ptr<const Packet> pkt, Ptr<Node> node);

   void SetupEnergy();
   static void TraceRemainingEnergy(Ptr<Node> node, double, double eng);
   static void TraceConsumedEnergy(Ptr<Node> node, Ptr<DeviceEnergyModel> model, 
                     Ptr<OutputStreamWrapper> stream, double, double eng);
   void GetTotalEnergyConsumption(Ptr<OutputStreamWrapper> stream, DeviceEnergyModelContainer& models);
      void GetMcrpRtts(Ptr<OutputStreamWrapper> stream, Ptr<OutputStreamWrapper> avgstream);
   void GetFinalResult(Ptr<OutputStreamWrapper> stream);
   void Execution();

   Ipv6RoutingHelper* GetIpv6RoutingHelper();
   void SetTraceFiles(string txname, string rxname);

   void SetMaliciousNodes(uint32_t left, uint32_t right, int defense, double ratio);
   void LinkMaliciousNodes();

private:
   string m_simu_name;
   double m_duration;
   double m_int_mean;
   double m_per_distance;
   double m_tx_power;
   uint32_t m_sensors;
   uint16_t m_port;
   E_ROUTE_POLICY m_routing;
 
   uint32_t m_tx_packets;
   uint32_t m_rx_packets;
   double m_tx_delay;
   double m_rx_delay;

   uint32_t m_pin_one;
   uint32_t m_pin_two;
   NodeContainer m_pin_nodes;
   NetDeviceContainer m_pin_devs;
   Ipv4InterfaceContainer m_pin_ifxs;

   Ptr<ExponentialRandomVariable> m_exp_random;

   NodeContainer m_all_nodes;
   NetDeviceContainer m_lrwpan_devs;
   NetDeviceContainer m_sixlowpan_devs;

   NodeContainer m_sensor_nodes;
   NetDeviceContainer m_sensor_devs;

   NodeContainer m_sink_nodes;
   NetDeviceContainer m_sink_devs;

   //Ipv4InterfaceContainer m_all_ifxs;
   Ipv6InterfaceContainer m_all_ifxs;

   double m_last_energy_time;
   double m_last_energy_amount;

   Ptr<OutputStreamWrapper> m_rxstream;
   Ptr<OutputStreamWrapper> m_txstream;
   Ptr<OutputStreamWrapper> m_rtstream;

   LrWpanHelper m_lrwpan_helper;
   SixLowPanHelper m_sixlowpan_helper;
   vector<MacCentredRoutingProtocol*> *m_mcrplist;
   McrpCache* m_mcrpcaches;

   int m_defense;
   double m_ratio;
};

#endif
