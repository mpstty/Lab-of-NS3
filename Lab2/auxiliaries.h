#ifndef _WSN_PLACE_ALLOCATION_H
#define _WSN_PLACE_ALLOCATION_H

#include <iostream>
#include <iomanip>
#include <cmath>
#include <ctime>
#include <map>
#include <string>
#include <iterator>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/mobility-module.h"
#include "ns3/lr-wpan-module.h"
#include "ns3/sixlowpan-module.h"
#include "ns3/sensor-module.h"
//#include <ns3/ofswitch13-module.h>

using namespace ns3;
using namespace std;
typedef enum{
   ROUTE_STATIC=0,
   ROUTE_DSDV=1,
   ROUTE_OLSR=2,
   ROUTE_AODV=3,
   ROUTE_DSR=4,
   ROUTE_STATIC6=5,
   ROUTE_DSDV6=6,
   ROUTE_OLSR6=7,
   ROUTE_MCRP=8,
   ROUTE_LEACH=9,
   ROUTE_LEACH_C=10,
}E_ROUTE_POLICY;

static string m_routing_name[16] = { "static", "dsdv", "olsr", "aodv", "dsr", 
                                "static_ipv6", "dsdv_ipv6", "olsr_ipv6", "mcrp", 
                                 "unknown"};
string GetRoutingName(int policy);

int GetRoutingIdx(string name);

string TrimHead(const string& s, const string& delimiters = " \f\n\r\t\v" );
string TrimTail(const string& s, const string& delimiters = " \f\n\r\t\v" );
string TrimEnds(const string& s, const string& delimiters = " \f\n\r\t\v" );

double ConvertDbmToW(double vDbm);

void PlaceInRectangle(NodeContainer nodelist, double X, double Y);

void PlaceInCircle(NodeContainer nodelist, double X, double Y, double R);

void PlaceInRegular(NodeContainer nodelist, double gap);

void PrintNodeInfo(Ptr<Node>);

void PrintNodes(NodeContainer nodelist);

Ptr<Node> FindNode(string name);
Ptr<Node> CreateNode(string name);
string GetNodeName(Ptr<Node> node);
bool IsSinkNode(Ptr<Node> node);
string GetPacketName(int type);

Ipv4Address GetIpv4GlobalAddress(Ptr<Node> node);
Ipv6Address GetIpv6GlobalAddress(Ptr<Node> node);
Ipv6Address GetIpv6LocalAddress(Ptr<Node> node);
string GetIpv4AddressString(Ipv4Address addr);

int64_t GetMicroSeconds(Time t);
Ptr<SensorNetDevice> GetSensorNetDevice(Ptr<Node> node);
Ptr<LrWpanNetDevice> GetLrWpanNetDevice(Ptr<Node> node);
Ptr<SixLowPanNetDevice> GetSixLowPanNetDevice(Ptr<Node> node);

#endif
