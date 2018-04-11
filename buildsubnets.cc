/*********************************************************
 *                                                       *
 *         w2   w3   w4               w1   w2    w3      *
 *          \   |   /                  \    |    /       *
 *    w1____ \  |  / ____w5             \   |   /        *
 *          \ \ | / /                    \  |  /         *
 *           \ \|/ /                      \ | /          *
 *           --------                    --------        *
 *  server+++|switch|======[Router]======|switch|        *
 *           --------                    --------        *
 *	         / /|\ \                      /   \          *
 *   w10____/ / | \ \____w6              /     \         *
 *           /  |  \                    /       \        *
 *          /   |   \                  /         \       *
 *	       w9   w8  w7                w4         w5      *
 *                                                       *
 *         10.1.1.0/24                 10.1.2.0/24       *
 *********************************************************/

#include <iostream>
#include <fstream>
#include <string>
#include <cassert>
#include "ns3/node.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/log.h"
#include "ns3/net-device.h"
#include "ns3/bridge-module.h"
#include <ns3/gnuplot.h>
#include "ns3/traffic-control-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE ("SIM_SUBNET_QUEUE");

Gnuplot2dDataset datasetRxDR, datasetRxPR, datasetDpDR, datasetDpPR;
Gnuplot *plotRxDR, *plotRxPR, *plotDpDR, *plotDpPR;

void Start2DPlotGraph(){
	NS_LOG_INFO("Plot: Start ...");

  	plotRxDR=new Gnuplot("datarate_recv.png","Received Traffic: (MB/sec)");
  	plotRxPR=new Gnuplot("pkgrate_recv.png","Received Traffic: (Packets/sec)");

  	plotDpDR=new Gnuplot("datarate_drop.png","Dropped Traffic: (MB/sec)");
  	plotDpPR=new Gnuplot("pkgrate_drop.png","Dropped Traffic: (Packets/sec)");

	plotRxDR->SetTerminal("png");
	plotRxPR->SetTerminal("png");

	plotDpDR->SetTerminal("png");
	plotDpPR->SetTerminal("png");

  	plotRxDR->SetLegend("time (sec)", "data volume (MB)");
  	plotRxPR->SetLegend("time (sec)", "packets");

  	plotDpDR->SetLegend("time (sec)", "data volume (MB)");
  	plotDpPR->SetLegend("time (sec)", "packets");

	plotRxDR->AppendExtra("set xrange [0:11]");
	plotRxPR->AppendExtra("set xrange [0:11]");

	plotRxDR->AppendExtra("set xrange [0:11]");
	plotRxPR->AppendExtra("set xrange [0:11]");

  	datasetRxDR.SetTitle("DRRecv (MB/sec)");
  	datasetRxPR.SetTitle("PRRecv (Packets/sec)");

  	datasetDpDR.SetTitle("DRDrop (MB/sec)");
  	datasetDpPR.SetTitle("PRDrop (Packets/sec)");

  	//datasetRxDR.SetStyle(Gnuplot2dDataset::LINES_POINTS);
  	//datasetRxPR.SetStyle(Gnuplot2dDataset::LINES_POINTS);
  	datasetRxDR.SetStyle(Gnuplot2dDataset::LINES);
  	datasetRxPR.SetStyle(Gnuplot2dDataset::LINES);

  	datasetDpDR.SetStyle(Gnuplot2dDataset::LINES);
  	datasetDpPR.SetStyle(Gnuplot2dDataset::LINES);
}

void End2DPlotGraph(){
	NS_LOG_INFO("Plot: Writing ...");

	plotRxDR->AddDataset(datasetRxDR);
	plotRxPR->AddDataset(datasetRxPR);

	plotDpDR->AddDataset(datasetDpDR);
	plotDpPR->AddDataset(datasetDpPR);

  	ofstream plotFileRxDR("scratch/log/datarate_recv.plot"); 
	ofstream plotFileRxPR("scratch/log/pktrate_recv.plot");

  	ofstream plotFileDpDR("scratch/log/datarate_drop.plot"); 
	ofstream plotFileDpPR("scratch/log/pktrate_drop.plot");

  	plotRxDR->GenerateOutput(plotFileRxDR);
  	plotRxPR->GenerateOutput(plotFileRxPR);

  	plotDpDR->GenerateOutput(plotFileDpDR);
  	plotDpPR->GenerateOutput(plotFileDpPR);

  	plotFileRxDR.close ();
  	plotFileRxPR.close ();

  	plotFileDpDR.close ();
  	plotFileDpPR.close ();

	NS_LOG_INFO("Plot: Done ...");
}

static uint32_t dataRxSize=0;
static uint32_t pktRxCnt=0;
static double drRecv=0.000;
static double prRecv=0.000;

static void SinkRx(Ptr<const Packet> pkt, const Address &address){
	dataRxSize+=pkt->GetSize();
	pktRxCnt+=1;
	double seconds = (double)Simulator::Now().GetSeconds()-1;
	drRecv = (double)dataRxSize/seconds;
	drRecv/=1024*1024; //in Mega Bytes
	prRecv=(double)pktRxCnt/seconds;
	datasetRxDR.Add(seconds,drRecv);
	datasetRxPR.Add(seconds,prRecv);
	return;
}


static uint32_t dataDpSize=0;
static uint32_t pktDpCnt=0;
static double drDrop=0.000;
static double prDrop=0.000;

static void SwitchDrop(Ptr<const Packet> pkt){
	dataDpSize+=pkt->GetSize();
	pktDpCnt+=1;
	drDrop=dataDpSize;
	prDrop=pktDpCnt;
	double seconds = (double)Simulator::Now().GetSeconds()-1;
	drDrop = (double)dataDpSize/seconds;
	drDrop/=1024*1024; //in Mega Bytes
	prDrop=(double)pktDpCnt/seconds;
	datasetDpDR.Add(seconds,drDrop );
	datasetDpPR.Add(seconds,prDrop );
	
	return;
}

int subnet_second(NodeContainer& wkstnNodes_1st, Ptr<Node> swtchNode_1st, NetDeviceContainer& swtchDevices_1st, Ipv4AddressHelper ipv4_1st, uint32_t queuesize){
	NodeContainer wkstnNodes;
	wkstnNodes.Create(5);

	Ptr<Node> swtchNode=CreateObject<Node>();
	Ptr<Node> routerNode=CreateObject<Node>();

	Names::Add("switch2",swtchNode);
	Names::Add("router",routerNode);

	NetDeviceContainer swtchDevices, wkstnDevices, routerDevices,csmaLink, p2pLink;

	CsmaHelper csma;

	csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
  	csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
	for (uint32_t i = 0; i < wkstnNodes.GetN(); i++){
		csmaLink = csma.Install(NodeContainer(wkstnNodes.Get(i), swtchNode));
		wkstnDevices.Add(csmaLink.Get(0));
		swtchDevices.Add(csmaLink.Get(1));
    }
	wkstnNodes_1st.Add(wkstnNodes);

	csma.SetChannelAttribute("DataRate", StringValue("1Gbps"));
  	csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(1)));
	csmaLink = csma.Install(NodeContainer(swtchNode_1st,routerNode));

	swtchDevices_1st.Add(csmaLink.Get(0));
	routerDevices.Add(csmaLink.Get(1));

	csmaLink = csma.Install(NodeContainer(swtchNode,routerNode));
	swtchDevices.Add(csmaLink.Get(0));
	routerDevices.Add(csmaLink.Get(1));

	BridgeHelper bridge;
	bridge.Install(swtchNode, swtchDevices);

	InternetStackHelper internet;
	internet.Install(NodeContainer(wkstnNodes,routerNode));

	Ipv4InterfaceContainer routerIfContainer;
	Ipv4AddressHelper ipv4;
	ipv4.SetBase("10.1.2.0", "255.255.255.0");
	routerIfContainer = ipv4.Assign(NetDeviceContainer(wkstnDevices,routerDevices.Get(1)));

	routerIfContainer = ipv4_1st.Assign(NetDeviceContainer(routerDevices.Get(0)));

	return 0;
}

int subnet_first(const int subnets, const string sendrate, uint32_t queuesize){
	NodeContainer wkstnNodes;
	wkstnNodes.Create(10);
	
	Ptr<Node> swtchNode=CreateObject<Node>();
	Ptr<Node> serverNode=CreateObject<Node>();

	Names::Add("switch",swtchNode);
	Names::Add("server",serverNode);

	NetDeviceContainer swtchDevices, wkstnDevices, serverDevices,csmaLink, p2pLink;

	CsmaHelper csma;

	csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
  	csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
	for (uint32_t i = 0; i < wkstnNodes.GetN(); i++){
		csmaLink = csma.Install(NodeContainer(wkstnNodes.Get(i), swtchNode));
		wkstnDevices.Add(csmaLink.Get(0));
		swtchDevices.Add(csmaLink.Get(1));
    }

	csma.SetQueue("ns3::DropTailQueue","MaxPackets", UintegerValue(queuesize));////default 100
	//csma.SetQueue("ns3::DropTailQueue","MaxBytes", UintegerValue(queuesize));

	csma.SetChannelAttribute("DataRate", StringValue("1Gbps"));
  	csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(1)));
	csmaLink = csma.Install(NodeContainer(serverNode, swtchNode));
	serverDevices.Add(csmaLink.Get(0));
	swtchDevices.Add(csmaLink.Get(1));

#if 0 /*use bridge for switch instead of openflow*/
	OpenFlowSwitchHelper swtch;
	Ptr<ns3::ofi::DropController> controller=CreateObject<ns3::ofi::DropController> ();
    swtch.Install(swtchNode, swtchDevices, controller);
#endif

	InternetStackHelper internet;
	internet.Install(NodeContainer(wkstnNodes,serverNode));

	Ipv4AddressHelper ipv4;
	ipv4.SetBase("10.1.1.0", "255.255.255.0");
	Ipv4InterfaceContainer serverIfContainer = ipv4.Assign(serverDevices);
	Ipv4InterfaceContainer wkstnIfContainer = ipv4.Assign(wkstnDevices);
	if(subnets == 2){
		subnet_second(wkstnNodes, swtchNode, swtchDevices, ipv4,queuesize);
	}

	BridgeHelper bridge;
	bridge.Install(swtchNode, swtchDevices);

	Ipv4GlobalRoutingHelper::PopulateRoutingTables();

	uint16_t port = 12345;
	InetSocketAddress serverSocketAddress(serverIfContainer.GetAddress(0), port);
	AddressValue serverAddress(serverSocketAddress);
	Address sinkSelfAddress(InetSocketAddress(Ipv4Address::GetAny(), port));

	ApplicationContainer sinkApplications, agentApplications; 

	//PacketSinkHelper sink("ns3::TcpSocketFactory", sinkSelfAddress);
	PacketSinkHelper sink("ns3::UdpSocketFactory", sinkSelfAddress);
	sinkApplications = sink.Install(serverNode);
	sinkApplications.Start(Seconds(0.0));
	sinkApplications.Stop(Seconds(10.0));
	
	//OnOffHelper agent("ns3::TcpSocketFactory",serverSocketAddress);
	OnOffHelper agent("ns3::UdpSocketFactory",serverSocketAddress);


#if 0
	agent.SetAttribute("OnTime", StringValue("ns3::UniformRandomVariable[Min=1][Max=2]"));
	agent.SetAttribute("OffTime",StringValue("ns3::UniformRandomVariable[Min=0][Max=1]"));
	agent.SetAttribute("OnTime", StringValue("ns3::ExponentialRandomVariable[Mean=1]"));
	agent.SetAttribute("OffTime",StringValue("ns3::ExponentialRandomVariable[Mean=2]"));
#endif
 	agent.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=4]"));
	agent.SetAttribute("OffTime",StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));

	agent.SetAttribute("PacketSize",UintegerValue(2048));
	agent.SetAttribute("DataRate",StringValue(sendrate));

	Ptr<OnOffApplication> agentTrace; 

	for(uint32_t i=0; i<wkstnNodes.GetN(); ++i){
      	agentApplications.Add(agent.Install(wkstnNodes.Get(i)));
#if 0
		agentTrace = DynamicCast<OnOffApplication>(agentApplications.Get(i));
		agentTrace->TraceConnectWithoutContext("Tx",MakeCallback(&AgentTx));
#endif
    }
	agentApplications.Start(Seconds (1.0));
	agentApplications.Stop(Seconds (10.0));

	Ipv4GlobalRoutingHelper globalRouting;
	//globalRouting.PopulateRoutingTables();
   	Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("scratch/log/sim_subnet_queue.route", ios::out);
   	globalRouting.PrintRoutingTableAllAt(Seconds(1), routingStream);

	Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback(SinkRx));
	Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::CsmaNetDevice/TxQueue/Drop", MakeCallback(SwitchDrop));
	//"/NodeList/[10,17]/DeviceList/*/$ns3::CsmaNetDevice/TxQueue/Drop"
	AsciiTraceHelper ascii;
	csma.EnableAsciiAll (ascii.CreateFileStream ("scratch/log/sim_subnet_queue.trace"));
	csma.EnablePcapAll ("scratch/log/sim_subnet_queue",true);

	return 0;	
}

#if 0
void testRN_UNI(){
	double min = 1.0;
	double max = 2.0;
	Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable> ();
	x->SetAttribute ("Min", DoubleValue (min));
	x->SetAttribute ("Max", DoubleValue (max));
	double value = x->GetValue ();
	cout<<value<<endl;
}


void testRN_EXP(){
	double mean = 2.0;
	double bound = 2.0;
	Ptr<ExponentialRandomVariable> x = CreateObject<ExponentialRandomVariable> ();
	x->SetAttribute ("Mean", DoubleValue (mean));
	x->SetAttribute ("Bound", DoubleValue (bound));
	double value = x->GetValue ();
	cout<<value<<endl;
}
#endif

int main(int argc,char **argv){

//	Time::SetResolution(Time::S);
//	testRN_EXP();
//	testRN_UNI();

	int subnetCnt=1; 
	string appRate="1Mbps";//"5Mbps";
	uint32_t queueSize=2000;

	CommandLine cmd; 
	cmd.AddValue("subnets","number of subnets [1]", subnetCnt);
	cmd.AddValue("apprate","rate of sending out packets [5Mbps]", appRate);
	cmd.AddValue("queuesize","Bytes of sending out packets [1000]", queueSize);
	cmd.Parse (argc, argv);

	NS_LOG_INFO("SUBNETS="<<subnetCnt<<", Send Rate="<<appRate<<", Queue Size="<<queueSize<<endl);

	Start2DPlotGraph();
	subnet_first(subnetCnt,appRate, queueSize);	

	Simulator::Stop(Seconds(10));
	Simulator::Run ();

	End2DPlotGraph();

//	NS_LOG_INFO("Total Sent Packets by Workstation: Count=" <<pktTxNum<<", Volume="<<pktTxSize<<"."<<endl);
	
	Simulator::Destroy ();

	return 0;
}

