#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>
#include <math.h>

#include <thread>
#include <mutex>
// #include <future>
// #include <ppltasks.h>    

#include <queue>
std::mutex mutex;

struct dataForRequest{
    dataForRequest(const std::string& _ip) : printerIP(_ip) {}
    std::string community = "public";
    std::string printerIP = "192.168.173.24";
};

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
    oid name2OID[MAX_OID_LEN];
    oid pagesOID[MAX_OID_LEN];
    size_t nameOIDLen = MAX_OID_LEN;
    size_t name2OIDLen = MAX_OID_LEN;
    size_t pagesOIDLen = MAX_OID_LEN;

    read_objid(".1.3.6.1.2.1.1.1", nameOID, &nameOIDLen);

    read_objid(".1.3.6.1.2.1.1.5.0", nameOID, &nameOIDLen); // Имя принтера ".1.3.6.1.2.1.1.5.0"
    read_objid(".1.3.6.1.2.1.25.3.2.1.3.1", name2OID, &name2OIDLen);//.1.3.6.1.2.1.25.3.2.1.3.1 модель принтера
    read_objid(".1.3.6.1.2.1.43.10.2.1.4.1.1", pagesOID, &pagesOIDLen); // Напечатанные страницы ".1.3.6.1.2.1.43.10.2.1.4.1.1"

    // Создание запроса PDU
    netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);
    netsnmp_pdu *response;

    snmp_add_null_var(pdu, nameOID, nameOIDLen);
    snmp_add_null_var(pdu, name2OID, name2OIDLen);
    snmp_add_null_var(pdu, pagesOID, pagesOIDLen);

    // Отправка запроса
    int status = snmp_synch_response(ss, pdu, &response);

    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        for (netsnmp_variable_list *vars = response->variables; vars; vars = vars->next_variable) {
            if (vars->type == ASN_OCTET_STR) {
                std::cout << "Name printer: " << std::string((char *)vars->val.string, vars->val_len) << std::endl;
            } else if (vars->type == ASN_COUNTER) {
                std::cout << "Value paper: " << *vars->val.integer << std::endl;
            }
        }
    } else {
        std::cerr << "Error in SNMP request. " <<data.printerIP << std::endl;
    }

    if (response) {
        snmp_free_pdu(response);
    }

    snmp_close(ss);
}   

// void queryPrinter(const dataForRequest &data){
//     std::cout<<data.printerIP<<std::endl;
// }

void searchSnmpAgents(std::string network, size_t netmask) { 
    size_t maxThreads = std::thread::hardware_concurrency(); // Ограничение по потокам 
    // std::vector<std::future<void>> futures;
    std::vector<std::thread> ggg;
    std::queue<dataForRequest> tasks; 
 
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

        // std::cout<<(b.printerIP)<<std::endl;
       ggg.emplace_back([ccc= b](){ //lock(mutex);
        // std::lock_guard<std::mutex>;
        // std::cout<<(b.printerIP)<<std::endl;
        mutex.lock();
        queryPrinter(ccc);
        mutex.unlock();
       });
    } 
 
    // Дожидаемся завершения всех потоков 
    for (auto &gg : ggg) { 
        gg.join(); 
    } 
 
    std::cout << "Все задачи завершены!" << std::endl; 
}
int main() {
    
//     dataForRequest b("192.168.173.26");
//     // queryPrinter(b);


//     dataForRequest d("192.168.173.24");

    searchSnmpAgents("192.168.8.0",24);
    return 0;
}