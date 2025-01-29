#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>
#include <math.h>
struct dataForRequest{
    dataForRequest(const std::string& _ip) : printerIP(_ip) {}
    std::string community = "public";
    std::string printerIP = "192.168.173.24";
};
// std::vector<dataForRequest> 

// const dataForRequest data
void queryPrinter(const dataForRequest &data) {
    // Инициализация SNMP
    init_snmp("printer_query");

    // Создание сессии
    struct snmp_session session, *ss;
    snmp_sess_init(&session);
    session.peername = strdup(data.printerIP.c_str());
    session.community = (u_char *)data.community.c_str();
    session.community_len = data.community.length();
    session.version = SNMP_VERSION_2c;

    ss = snmp_open(&session);
    if (!ss) {
        snmp_perror("snmp_open");
        return;
    }

    // Установка OID
    oid nameOID[MAX_OID_LEN];
    oid pagesOID[MAX_OID_LEN];
    size_t nameOIDLen = MAX_OID_LEN;
    size_t pagesOIDLen = MAX_OID_LEN;

    read_objid(".1.3.6.1.2.1.1.5.0", nameOID, &nameOIDLen); // Имя принтера
    //.1.3.6.1.2.1.25.3.2.1.3.1 модель принтера
    read_objid(".1.3.6.1.2.1.43.10.2.1.4.1.1", pagesOID, &pagesOIDLen); // Напечатанные страницы ".1.3.6.1.2.1.43.10.2.1.4.1.1"

    // Создание запроса PDU
    netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);
    netsnmp_pdu *response;

    snmp_add_null_var(pdu, nameOID, nameOIDLen);
    snmp_add_null_var(pdu, pagesOID, pagesOIDLen);

    // Отправка запроса
    int status = snmp_synch_response(ss, pdu, &response);

    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        for (netsnmp_variable_list *vars = response->variables; vars; vars = vars->next_variable) {
//             if (vars) {
//     std::cout << "vars->type: " << static_cast<int>(vars->type) << std::endl;
// } else {
//     std::cerr << "Error: vars is null." << std::endl;
// }
            if (vars->type == ASN_OCTET_STR) {
                std::cout << "\nName printer: " << std::string((char *)vars->val.string, vars->val_len) ;
            } else if (vars->type == ASN_COUNTER) {
                std::cout << "\nValue paper: " << *vars->val.integer ;
            }
        }
        std::cout<<std::endl;
    } else {
        std::cerr << "Error in SNMP request." <<data.printerIP << std::endl;
    }

    if (response) {
        snmp_free_pdu(response);
    }

    snmp_close(ss);
}   

void searchSnmpAgents(std::string network, size_t netmask){
    int countHosts=pow(2,32-netmask)-2;
   std::cout<<countHosts<<std::endl;
   int ip[4]{0,0,0,0};
   std::cout<<ip[0]<<'.'<<ip[1]<<'.'<<ip[2]<<'.'<<ip[3]<<std::endl;

   std::stringstream s;
   s<<network;
   for(auto &i:ip)
   {
   std::string a;
   std::getline(s,a,'.');
    i=std::stoi(a);
   }
   std::cout<<ip[0]<<'.'<<ip[1]<<'.'<<ip[2]<<'.'<<ip[3]<<std::endl;
   for(int i=1;i<=countHosts;i++)
   {
    std::string a=std::to_string(ip[0])+'.'+std::to_string(ip[1])+'.'+std::to_string(ip[2]+(i/256))+'.'+std::to_string((ip[3]+i)%256);
    dataForRequest b(a);
    queryPrinter(b);
    std::cout<<b.printerIP<<"/"<<b.community<<std::endl;
   }
}


int main() {
    
    searchSnmpAgents("192.168.173.0",24);
    return 0;
}