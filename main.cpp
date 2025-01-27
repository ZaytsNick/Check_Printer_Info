#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <iostream>
#include <string>

void queryPrinter(const std::string &ip, const std::string &community) {
    // Инициализация SNMP
    init_snmp("printer_query");

    // Создание сессии
    struct snmp_session session, *ss;
    snmp_sess_init(&session);
    session.peername = strdup(ip.c_str());
    session.community = (u_char *)community.c_str();
    session.community_len = community.length();
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
        std::cerr << "Error in SNMP request." << std::endl;
    }

    if (response) {
        snmp_free_pdu(response);
    }

    snmp_close(ss);
}

int main() {
    // std::string printerIP;
    // std::string community;

  std::string printerIP = "192.168.173.24";//"192.168.173.24";  // IP принтера
    std::string community = "public"; // SNMP Community

    // std::cout << "Enter printer IP: ";
    // // std::cin >> printerIP;
    // std::cout << "Enter SNMP community (default: public): ";
    // // std::cin >> community;

    if (community.empty()) {
        community = "public";
    }

    queryPrinter(printerIP, community);

    return 0;
}