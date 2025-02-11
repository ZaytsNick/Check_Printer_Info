#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>
#include <math.h>

#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>

// #include <array>
#include <chrono>
// #include <cstdlib>
// #include <memory>
// #include <string>
#include <thread>



struct dataForRequest{
    dataForRequest(const std::string& _ip) : printerIP(_ip) {}
    std::string community = "public";
    std::string printerIP = "192.168.173.24";
};

const std::string PRINTER_NAME_OID = ".1.3.6.1.2.1.1.5.0";
const std::string PRINTER_MODEL_OID = ".1.3.6.1.2.1.25.3.2.1.3.1";
const std::string PRINTED_PAGES_OID = ".1.3.6.1.2.1.43.10.2.1.4.1.1";


snmp_session *create_snmp_session(const std::string &printerIP, const std::string &community) {
    snmp_session session;
    snmp_sess_init(&session);
    session.peername = strdup(printerIP.c_str());
    session.community = (u_char *)community.c_str();
    session.community_len = community.length();
    session.version = SNMP_VERSION_2c;

    return snmp_open(&session);
}

void close_snmp_session(snmp_session* session) {
    if (session) {
        if (session->peername) {
            free(session->peername); // Освобождение памяти для IP-адреса
            session->peername = NULL;
        }
        snmp_close(session); // Закрытие сессии
    }
}

void add_oid_to_pdu(netsnmp_pdu *pdu, const std::string &oid_str) {
    oid oid_array[MAX_OID_LEN];
    size_t oid_len = MAX_OID_LEN;
    read_objid(oid_str.c_str(), oid_array, &oid_len);
    snmp_add_null_var(pdu, oid_array, oid_len);
}

struct tmpMetric{
    tmpMetric(const std::string& _ip) : ip(_ip) {}
std::string ip="0";
  std::string name="0";
  std::string model="0";
//   std::string pages="0";
int pages=0;
};

const char* snmp_type_to_string(int type) {
    switch (type) {
        case ASN_INTEGER:       return "INTEGER";
        case ASN_OCTET_STR:     return "OCTET STRING";
        case ASN_NULL:          return "NULL";
        case ASN_OBJECT_ID:     return "OBJECT IDENTIFIER";
        case ASN_IPADDRESS:     return "IPADDRESS";
        case ASN_COUNTER:       return "COUNTER32";
        case ASN_GAUGE:         return "GAUGE32";
        case ASN_TIMETICKS:     return "TIMETICKS";
        case ASN_OPAQUE:        return "OPAQUE";
        case ASN_COUNTER64:     return "COUNTER64";
        // case ASN_UNSIGNED:      return "UNSIGNED32";
        default:                return "UNKNOWN";
    }
}

// void process_snmp_response(netsnmp_pdu *response) {
void process_snmp_response(netsnmp_pdu *response, tmpMetric& tmp) {
    // tmpMetric tmp;
    bool firstTray=true;
    for (netsnmp_variable_list *vars = response->variables; vars; vars = vars->next_variable) {
        // std::cout<<snmp_type_to_string(vars->type)<<std::endl;
        if (vars->type == ASN_OCTET_STR && firstTray){
            std::cout << "Name printer: " << std::string((char *)vars->val.string, vars->val_len) << std::endl;
            tmp.name=std::string((char *)vars->val.string, vars->val_len);
            firstTray=false;
        } else if (vars->type == ASN_OCTET_STR && !firstTray){
            std::cout << "Model printer: " << std::string((char *)vars->val.string, vars->val_len) << std::endl;
            tmp.model=std::string((char *)vars->val.string, vars->val_len);
        } else if (vars->type == ASN_COUNTER) {
            std::cout << "Value paper: " << *vars->val.integer << std::endl;
            tmp.pages=*vars->val.integer;
        }
    }
    // return tmp;
}
// void queryPrinter(const dataForRequest data) {
tmpMetric queryPrinter(const dataForRequest data) {
    tmpMetric tmp(data.printerIP);

    init_snmp("printer_query");

    // Создание SNMP-сессии
    snmp_session *ss = create_snmp_session(data.printerIP, data.community);

    netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);    // Создание PDU для SNMP-запроса
    add_oid_to_pdu(pdu, PRINTER_NAME_OID);
    add_oid_to_pdu(pdu, PRINTER_MODEL_OID);
    add_oid_to_pdu(pdu, PRINTED_PAGES_OID);

    // Ответ от SNMP-сервера
    netsnmp_pdu *response = nullptr;  // Инициализация на случай ошибки
    if (!ss) {
        snmp_perror("snmp_open");
        std::cout<<"gg"<<std::endl;
        return tmp;// return;
    }
    int status = snmp_synch_response(ss, pdu, &response);
    close_snmp_session(ss);

    // Обработка успешного ответа
    if (status == STAT_SUCCESS && response && response->errstat == SNMP_ERR_NOERROR) {
         process_snmp_response(response, tmp);
    } else {
        std::cerr << "Error in SNMP request. " << data.printerIP << std::endl;
    }
    close_snmp_session(ss);
    // Освобождение PDU
    if (response) {
        snmp_free_pdu(response);
    }
    return tmp;
}

void searchSnmpAgents(std::string network, size_t netmask) { 
    // Проверка маски 
    if (netmask < 1 || netmask > 30) { 
        throw std::runtime_error("Incorrect netmask"); 
    } 
 
    int countHosts = (1 << (32 - netmask)) - 2; // Оптимизированный подсчёт 
 
    // Разбор IP 
    int ip[4]{0, 0, 0, 0}; 
    std::stringstream s(network); 
    for (auto &i : ip) { 
        std::string a; 
        std::getline(s, a, '.'); 
        i = std::stoi(a); 
    } 
 
    // Базовый IP в 32-битном формате 
    uint32_t baseIp = (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3]; 
 
    // Обход диапазона IP 
    for (int i = 1; i <= countHosts; i++) { 
        uint32_t newIp = baseIp + i; 
        std::string ipAddress = std::to_string((newIp >> 24) & 0xFF) + "." + 
                                std::to_string((newIp >> 16) & 0xFF) + "." + 
                                std::to_string((newIp >> 8) & 0xFF) + "." + 
                                std::to_string(newIp & 0xFF); 
 
        dataForRequest b(ipAddress); 
        queryPrinter(b);
  } 
 
 
    std::cout << "Все задачи завершены!" << std::endl; 
}





void startPrometeus() {
  std::cout<<"start"<<std::endl;
  using namespace prometheus;

  // create an http server running on port 8080
  Exposer exposer{"127.0.0.1:8080"};

  auto registry = std::make_shared<Registry>();

//   auto& pagesPriter = BuildGauge()//BuildCounter()
//                              .Name("pages_printed")
//                              .Help("number_of_pages_printed_on_a_printer")
//                              .Register(*registry);
//   dataForRequest b("192.168.173.24");
//     tmpMetric tmp=queryPrinter(b);
//   auto& printPag=pagesPriter.Add({{"ip_address",tmp.ip},{"Name",tmp.name},{"Model",tmp.model}});
    // auto& printPag = pagesPrinted.Add({{"ip_address", tmp.ip}, {"Name", tmp.name}, {"Model", tmp.model}});
  exposer.RegisterCollectable(registry);
  
  auto start_time = std::chrono::steady_clock::now();
  
// while (true) {
while(std::chrono::steady_clock::now()-start_time<std::chrono::seconds(60)){
     auto& pagesPriter = BuildGauge()//BuildCounter()
                             .Name("pages_printed")
                             .Help("number_of_pages_printed_on_a_printer")
                             .Register(*registry);
  dataForRequest b("192.168.173.24");
    tmpMetric tmp=queryPrinter(b);
  auto& printPag=pagesPriter.Add({{"ip_address",tmp.ip},{"Name",tmp.name},{"Model",tmp.model}});
    // tmp = queryPrinter(b);  // Запрашиваем обновлённые данные
    printPag.Set(tmp.pages);  // Устанавливаем значение в метрику
    std::this_thread::sleep_for(std::chrono::seconds(1));  // Обновляем раз в 5 секунд
  }


  std::cout<<"end"<<std::endl;
   
  return ;
  }


int main() {
    // Инициализация SNMP
    // init_snmp("printer_query");
    
    // dataForRequest b("192.168.173.24");
    // std::cout<<b.printerIP<<std::endl;
    // queryPrinter(b);
    // dataForRequest d("192.168.173.26");
    // queryPrinter(d);

    // b.printerIP="192.168.173.24";
    // queryPrinter(b);
    // searchSnmpAgents("192.168.173.0",24);


    // auto start= std::chrono::high_resolution_clock::now();
    // searchSnmpAgents("192.168.173.0",24);
    // auto end= std::chrono::high_resolution_clock::now();
    // std::chrono::duration<double> dur=end-start;
    // std::cout<<"time: "<<dur.count()<<std::endl;
    startPrometeus();
    return 0;
}




