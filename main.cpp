// #include <filesystem>
#include <fstream>
#include <iostream>
// #include <istream>
#include <chrono>
// #include <future>
#include <math.h>
// #include <sstream>
#include <string>
#include <thread>
#include <vector>
// #include <mutex>

#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <nlohmann/json.hpp>

struct dataForRequest {
  dataForRequest(const std::string &_ip) : printerIP(_ip) {}
  dataForRequest(const std::string &_community, const std::string &_ip)
      : printerIP(_ip), community(_community) {}
  std::string community = "public";
  std::string printerIP = "192.168.173.24";
};

// #define PRINTER_NAME_OID ".1.3.6.1.2.1.1.5.0"
#define PRINTER_SN_OID "1.3.6.1.2.1.43.5.1.1.17.1"
#define PRINTER_MODEL_OID ".1.3.6.1.2.1.25.3.2.1.3.1"
#define PRINTED_PAGES_OID ".1.3.6.1.2.1.43.10.2.1.4.1.1"

snmp_session *create_snmp_session(dataForRequest &snmpAgent) {
  // snmp_session session;
  netsnmp_session session;
  snmp_sess_init(&session);
  session.peername = strdup(snmpAgent.printerIP.c_str());
  session.community = (u_char *)snmpAgent.community.c_str();
  session.community_len = snmpAgent.community.length();
  session.version = SNMP_VERSION_2c;

  return snmp_open(&session);
}

void close_snmp_session(snmp_session *session) {
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

struct tmpMetric {
  tmpMetric(const std::string &_ip) : ip(_ip) {}
  std::string ip = "0";
  std::string name = "0";
  std::string model = "0";
  bool online = 0;
  //   std::string pages="0";
  int pages = 0;
};

void process_snmp_response(netsnmp_pdu *response, tmpMetric &tmp) {
  bool firstTray = true;
  for (netsnmp_variable_list *vars = response->variables; vars;
       vars = vars->next_variable) {
    // std::cout<<snmp_type_to_string(vars->type)<<std::endl;
    if (vars->type == ASN_OCTET_STR && firstTray) {
      std::cout << "SN printer: "
                << std::string((char *)vars->val.string, vars->val_len)
                << std::endl;
      tmp.model = std::string((char *)vars->val.string, vars->val_len);
      firstTray = false;
    } else if (vars->type == ASN_OCTET_STR && !firstTray) {
      std::cout << "Name printer: "
                << std::string((char *)vars->val.string, vars->val_len)
                << std::endl;
      tmp.name = std::string((char *)vars->val.string, vars->val_len);
    } else if (vars->type == ASN_COUNTER) {
      std::cout << "Value paper: " << *vars->val.integer << std::endl;
      tmp.pages = *vars->val.integer;
    }
  }
  if (tmp.pages != 0) {
    tmp.online = 1;
  }
}

tmpMetric queryPrinter(/*const*/ dataForRequest data) {
  tmpMetric tmp(data.printerIP);
  snmp_session *ss = create_snmp_session(data);
  netsnmp_pdu *pdu =
      snmp_pdu_create(SNMP_MSG_GET); // Создание PDU для SNMP-запроса
  add_oid_to_pdu(pdu, PRINTER_SN_OID);
  add_oid_to_pdu(pdu, PRINTER_MODEL_OID);
  add_oid_to_pdu(pdu, PRINTED_PAGES_OID);

  // Ответ от SNMP-сервера
  netsnmp_pdu *response = nullptr; // Инициализация на случай ошибки
  if (!ss) {
    snmp_perror("snmp_open");
    tmp.ip = "0";
    return tmp; // return;
  }
  int status = snmp_synch_response(ss, pdu, &response);
  close_snmp_session(ss);

  // Обработка успешного ответа
  if (status == STAT_SUCCESS && response &&
      response->errstat == SNMP_ERR_NOERROR) {
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

void startPrometeus(std::vector<dataForRequest> &snmpAgents) {
  std::cout << "start" << std::endl;
  using namespace prometheus;

  std::string srv_ip;
  std::ifstream ipLists("ipLists.json");
  if (ipLists.is_open()) {
    nlohmann::json dict;
    ipLists >> dict;
    // if (dict["Srv_ip"]) {
      srv_ip = dict["Srv_ip"];
    // }
  }
  ipLists.close();
  // create an http server running on port 8080
  Exposer exposer{srv_ip}; //{"192.168.173.10:8100"};
  // Exposer exposer{"127.0.0.1:8080"};
  auto registry = std::make_shared<Registry>();
  exposer.RegisterCollectable(registry);
  auto start_time = std::chrono::steady_clock::now();

  // while (true) {
  while (std::chrono::steady_clock::now() - start_time <
         std::chrono::seconds(600)) {
    auto &pagesPriter = BuildGauge() // BuildCounter()
                            .Name("pages_printed")
                            .Help("number_of_pages_printed_on_a_printer")
                            .Register(*registry);
    auto &offlinePrinters = BuildGauge() // BuildCounter()
                                .Name("offline_printer")
                                .Help("this_printer_not_found")
                                .Register(*registry);
    for (auto &snmpAgent : snmpAgents) {
      tmpMetric conpletedRequest = queryPrinter(snmpAgent);
      // if (conpletedRequest.name != "0" || conpletedRequest.model != "0") {
      std::string online;
      if (conpletedRequest.online) {
        online = "online";
      } else {
        online = "offline";
      }

      auto &printPag = pagesPriter.Add({{"Online", online},
                                        {"ip_address", conpletedRequest.ip},
                                        {"Name", conpletedRequest.name},
                                        {"SN", conpletedRequest.model}});
      // tmp = queryPrinter(b);  // Запрашиваем обновлённые данные
      printPag.Set(conpletedRequest.pages); // Устанавливаем значение в метрику
      std::this_thread::sleep_for(
          std::chrono::seconds(5)); // Обновляем раз в 5 секунд
      // } else {
      // auto &offlinePrinter = offlinePrinters.Add(
      //     {"ip_address", conpletedRequest.ip}, {"status", "offline"});
      // }
    }
  }
  std::cout << "end" << std::endl;

  return;
}

std::vector<dataForRequest> readTheListOfSnmpAgents() {
  std::cout << "start read" << std::endl;
  std::vector<dataForRequest> tmp;
  std::ifstream ipLists("ipLists.json");
  if (ipLists.is_open()) {
    nlohmann::json dict;
    ipLists >> dict;
    if (dict.contains("Snmp_Agent") && dict["Snmp_Agent"].is_array()) {
      tmp.reserve(dict["Snmp_Agent"].size());
      for (auto &agent : dict["Snmp_Agent"]) {
        tmp.emplace_back(agent["community"], agent["printer_IP"]);
      }
      ipLists.close();
      std::cout << "end read" << std::endl;
      return tmp;
    } else {
    }
  } else {
    std::cerr << "Failed to open file!" << std::endl;
    return {}; // Возвращаем пустой вектор
  }

  throw std::runtime_error("Unhandled exception");
}

int main() {
  // Инициализация SNMP
  init_snmp("printer_query");

  std::vector<dataForRequest> ddd = readTheListOfSnmpAgents();
  for (auto &sss : ddd) {
    std::cout << sss.community << "|" << sss.printerIP << std::endl;
  }
  startPrometeus(ddd);

  return 0;
}