#include "auxiliaries.h"
//#include "wifibase.h"
#include "lrwpanbase.h"

int main(int argc, char **argv){
   LogComponentEnable("SimuAuxiliaries", LOG_LEVEL_ALL);
   //LogComponentEnable("WifiTestBox", LOG_LEVEL_ALL);
   LogComponentEnable("LrWpanTestBox", LOG_LEVEL_ALL);
   char simName[10];
   double duration = 60.00;
   double distance = 100.00;
   int sensors = 30;
   double txPower = 20.00;
   double txMean = 1.00;
   int routing = ROUTE_MCRP;


   char mals[10] = "\0";
   string policy = "";

   memset(simName, 0x00, sizeof(simName));
   strcpy(simName, "mcrp");

   CommandLine cmd;
   cmd.AddValue ("name", "Simulation name", simName);
   cmd.AddValue ("mean", "Transimission Mean (seconds)", txMean);
   cmd.AddValue ("duration", "Simulation time (seconds)", duration);
   cmd.AddValue ("distance", "Distance between 2 nodes", distance);
   cmd.AddValue ("sensors", "Number of Sensor Nodes ", sensors);
   cmd.AddValue ("power", "Transmission Power(w)", txPower);
   cmd.AddValue ("policy", "Routing Protocol", policy);
   cmd.AddValue ("mals", "Malicious Nodes ID (id,id)", mals);
   cmd.Parse (argc, argv);

   uint32_t mA = 0, mB = 0;
   int mD = 0;
   double mR = 0.00;
   if(mals[0] != '\0'){
      string malsStr = string(mals)+",";
		string subret = "";
		string delimiter = ",";
		size_t pos = 0, field=0;
		while ((pos = malsStr.find(delimiter)) != std::string::npos  && ++field) {
			subret = malsStr.substr(0, pos);
			switch(field){
				case 1:
					mA = stoi(subret);
					break;
				case 2:
					mB = stoi(subret);
					break;
				case 3:
					mD = stoi(subret);
               break;
				case 4:
					mR = stof(subret);
               break;
            default:
               break; 
         }
         malsStr.erase(0, pos + delimiter.length());
      }
   }

   routing = GetRoutingIdx(policy);
   cout<<"##Policy: "<<policy<<", id="<<routing<<", Malicious="<<mals<<"("<<mA<<", "<<mB<<","<<mD<<")."<<endl;

   NS_ASSERT_MSG(routing!=-1, "UnKnown Routing Protocol");

   if(mA == 0 || mB == 0){
			mD = mA = mB = 0;
   }
   LrWpanTestBox lrwpanTestbox(txMean, distance, sensors, txPower, routing, duration); 
   lrwpanTestbox.SetMaliciousNodes(mA, mB, mD, mR);
   lrwpanTestbox.Execution();

   return 0;
}
