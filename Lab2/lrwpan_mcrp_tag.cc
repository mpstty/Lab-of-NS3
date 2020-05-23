#include "auxiliaries.h"
#include "lrwpan_mcrp_tag.h"
//using namespace ns3;

NS_LOG_COMPONENT_DEFINE("McrpPacketTag"); 
NS_OBJECT_ENSURE_REGISTERED(McrpPktTag);

McrpPktTag::McrpPktTag(){
   memset(&m_infos, 0x00, sizeof(m_infos));
   memset(&m_hops, 0x00, sizeof(m_hops));
   memset(m_address, 0x00, sizeof(m_address));
   m_time = 0.00;
}

McrpPktTag::~McrpPktTag(){
   NS_LOG_FUNCTION("Destroyed");
}

int McrpPktTag::GetPktType() const{ 
   int n = 0; 
   n |= (m_infos>>13) & 7; 
   return n;
}

int McrpPktTag::GetPktHops() const{
   int n = 0; 
   n = int(m_hops);
   return n;
}

int McrpPktTag::GetPktSeq() const { 
   int n = 0; 
   n |=  m_infos & 8191;
   return n;
}

Address McrpPktTag::GetPktAddress() const{
   Mac16Address addr;
   addr.CopyFrom(m_address);
   return Address(addr);
}

double McrpPktTag::GetPktTime() const{
   return m_time;
}

double McrpPktTag::GetRttTime() const{
   return m_rtt;
}

void McrpPktTag::SetPktType(int n){ 
   m_infos |= (n<<13) & (7<<13);
}

void McrpPktTag::SetPktHops(int n){ 
   m_hops = (uint8_t)n;
}

void McrpPktTag::SetPktSeq(int n){ 
   m_infos |= n & (8191);
}

void McrpPktTag::SetPktAddress(Address addr){
   (Mac16Address::ConvertFrom(addr)).CopyTo(m_address); 
}

void McrpPktTag::SetPktTime(double ft){
   m_time = ft;
}

void McrpPktTag::SetRttTime(double ft){
   m_rtt = ft;
}

TypeId McrpPktTag::GetTypeId(){
   static TypeId tid = TypeId ("ns3::McrpPktTag")
      .SetParent<Tag> ()
      .AddConstructor<McrpPktTag>()
   ;   
   return tid;
}

TypeId McrpPktTag::GetInstanceTypeId (void) const { 
   return GetTypeId(); 
}

uint32_t McrpPktTag::GetSerializedSize (void) const { 
   uint32_t size = 0;
   size += sizeof(m_infos);
   size += sizeof(m_hops);
   size += sizeof(m_address);
   size += sizeof(m_time);
   size += sizeof(m_rtt);
   return size;
}

void McrpPktTag::Serialize(TagBuffer i) const { 
   i.Write((uint8_t*)&m_infos, sizeof(m_infos));
   i.Write((uint8_t*)&m_hops, sizeof(m_hops));
   i.Write((uint8_t*)m_address, sizeof(m_address)); 
   i.Write((uint8_t*)&m_time, sizeof(m_time));
   i.Write((uint8_t*)&m_rtt, sizeof(m_rtt));
}

void McrpPktTag::Deserialize (TagBuffer i) { 
   i.Read((uint8_t*)&m_infos, sizeof(m_infos)); 
   i.Read((uint8_t*)&m_hops, sizeof(m_hops)); 
   i.Read((uint8_t*)m_address, sizeof(m_address)); 
   i.Read((uint8_t*)&m_time, sizeof(m_time)); 
   i.Read((uint8_t*)&m_rtt, sizeof(m_rtt)); 
}

void McrpPktTag::Print(ostream &os) const {  
   NS_LOG_FUNCTION_NOARGS();
   NS_LOG_INFO("    Hops="<<GetPktHops());
   NS_LOG_INFO("    Seq="<<GetPktSeq());
   NS_LOG_INFO("    Original="<<GetPktAddress());
   NS_LOG_INFO("    Time="<<GetPktTime());
   NS_LOG_INFO("    RTT="<<GetRttTime());
}

McrpCache::McrpCache(){
   m_cachelist = new list<McrpCache::Record*>();
   m_current_recordit = m_cachelist->begin();
}

McrpCache::~McrpCache(){
   list<McrpCache::Record *>::iterator it;
   for(it=m_cachelist->begin(); it!=m_cachelist->end(); it++){
      delete (*it);
   }
   m_cachelist->clear();
   delete m_cachelist;
}

bool McrpCache::Insert(McrpCache::Record *r){
   if(Select(r->m_seq, r->m_txtime, r->m_srcaddr) == NULL){
      m_cachelist->push_back(r);
      return true;
   }
   return false;
}

bool McrpCache::Insert(McrpCache::Record *r, bool fullcheck){
   bool found = false;
   if(fullcheck==true){
      if(Select(r->m_seq, r->m_txtime, r->m_srcaddr) != NULL){
         found = true;
      }
   }
   else{
      list<McrpCache::Record *>::iterator it;
      for(it=m_cachelist->begin(); it!=m_cachelist->end(); it++){
         if( (*it)->m_ipv6_srcaddr == r->m_ipv6_srcaddr ){
            found = true;
            break;
         }
      }
   }
   if(found==false){
      m_cachelist->push_back(r);
      return true;
   }
   return false;
}

bool McrpCache::Insert(int seq, double txt, Address src, Ptr<const Packet> pkt, double rxt){
   if(Select(seq, txt, src) == NULL){
      McrpCache::Record* record = new McrpCache::Record();
      record->m_seq = seq;
      record->m_srcaddr = src;
      record->m_txtime = txt;
      record->m_rxtime = rxt;
      record->m_packet= pkt->Copy();
      m_cachelist->push_back(record);
      return true;
   }
   return false;
}

McrpCache::Record* McrpCache::Select(int seq, double txt, Address src){
   list<McrpCache::Record *>::iterator it;
   for(it=m_cachelist->begin(); it!=m_cachelist->end(); it++){
      if((*it)->m_seq == seq &&
               (*it)->m_srcaddr == src &&
                  (*it)->m_txtime == txt ){
         return (*it);
      }
   }
   return NULL;
}

Ptr<Packet> McrpCache::GetCurrentPacket(){
   list<McrpCache::Record *>::iterator it;
   for(it=m_cachelist->begin(); it!=m_cachelist->end(); it++){
      McrpCache::Record* rec = (*it);
      if(rec->m_status == 0){
         rec->m_status = 1;
         return rec->m_packet;
      }
   }
   return NULL;
}

void McrpCache::Print(){
   NS_LOG_FUNCTION("Print Caches: ");
   NS_LOG_UNCOND("----------------------------------");
   list<McrpCache::Record *>::iterator it;
   int i=0;
   for(it=m_cachelist->begin(); it!=m_cachelist->end(); it++){
      McrpCache::Record* r = (*it);
      ostringstream msgos;
      msgos<<"  #"<<++i<<", "<<r->m_seq<<", "<<r->m_srcaddr<<", "<<r->m_txtime
                                 <<", ("<<r->m_xloc<<", "<<r->m_yloc<<")"<<endl;

      NS_LOG_UNCOND(msgos.str());
   }
}

list<McrpCache::Record *>* McrpCache::GetAllRecords(){
   return m_cachelist;
}
