/******************************************************************************\
 *  _   ___     ____  __               _                                      *
 * | | | \ \___/ /  \/  | ___ __ _ ___| |_                                    *
 * | |_| |\     /| |\/| |/ __/ _` / __| __|                                   *
 * |  _  | \ - / | |  | | (_| (_| \__ \ |_                                    *
 * |_| |_|  \_/  |_|  |_|\___\__,_|___/\__|                                   *
 *                                                                            *
 * This file is part of the HAMcast project.                                  *
 *                                                                            *
 * HAMcast is free software: you can redistribute it and/or modify            *
 * it under the terms of the GNU Lesser General Public License as published   *
 * by the Free Software Foundation, either version 3 of the License, or       *
 * (at your option) any later version.                                        *
 *                                                                            *
 * HAMcast is distributed in the hope that it will be useful,                 *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                       *
 * See the GNU Lesser General Public License for more details.                *
 *                                                                            *
 * You should have received a copy of the GNU Lesser General Public License   *
 * along with HAMcast. If not, see <http://www.gnu.org/licenses/>.            *
 *                                                                            *
 * Contact: HAMcast support <hamcast-support@informatik.haw-hamburg.de>       *
\******************************************************************************/

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h> 
#include <net/if.h>
#include <string>

#include <algorithm>
#include <cctype>

#include "ip_module.hpp"
#include "ip_instance.hpp"
#include "ip_exceptions.hpp"

#include "hamcast/uri.hpp"
#include "hamcast/hamcast.hpp"
#include "hamcast/hamcast_logging.h"
#include "hamcast/hamcast_module.h"

using namespace ipm;
using std::string;

enum discovery_type {
     OFF, LIGHT, FULL
};
enum discovery_ip_version {
     IP4, IP6, IPALL
};

void *get_in_addr (struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

inline ip_instance* self(hc_module_instance_t instance)
{
    return reinterpret_cast<ip_instance*>(instance);
}

hc_uri_list_t uri_list (const std::set<hamcast::uri> uriset)
{
    HC_LOG_TRACE("Convert set to uri list.");

    hc_uri_list_t res;
    res.uri_str = NULL;
    res.uri_obj = NULL;
    res.type    = HC_IGNORED;
    res.next    = NULL;

    hc_uri_list_t *tmp = &res;
    std::set<hamcast::uri>::iterator it;
    for (it = uriset.begin(); it != uriset.end(); ++it) {
        tmp->uri_str = NULL;
        tmp->uri_obj = new hamcast::uri(*it);
        tmp->type    = HC_IGNORED;
        tmp->next    = NULL;
        tmp->next    = new hc_uri_list_t();
        tmp          = tmp->next;
    }
    delete (tmp->next);
    tmp->next = NULL;
    return res;
}

hc_uri_list_t uri_list (std::vector<hamcast::uri>& urivec)
{
    HC_LOG_TRACE("Convert set to uri list.");

    hc_uri_list_t res;
    res.uri_str = NULL;
    res.uri_obj = NULL;
    res.type    = HC_IGNORED;
    res.next    = NULL;

    hc_uri_list_t *tmp = &res;
    std::vector<hamcast::uri>::iterator it;
    for (it = urivec.begin(); it != urivec.end(); ++it) {
        tmp->uri_str = NULL;
        tmp->uri_obj = new hamcast::uri(*it);
        tmp->type    = HC_IGNORED;
        tmp->next    = NULL;
        tmp->next    = new hc_uri_list_t();
        tmp          = tmp->next;
    }
    delete (tmp->next);
    tmp->next = NULL;
    return res;
}

hc_uri_list_t uri_list (std::vector<std::pair<hamcast::uri, int> >& urivec)
{
    HC_LOG_TRACE("Convert set to uri list.");

    hc_uri_list_t res;
    res.uri_str = NULL;
    res.uri_obj = NULL;
    res.type    = HC_IGNORED;
    res.next    = NULL;

    hc_uri_list_t *tmp = &res;
    std::vector<std::pair<hamcast::uri, int> >::iterator it;
    for (it = urivec.begin(); it != urivec.end(); ++it) {
        tmp->uri_str = NULL;
        tmp->uri_obj = new hamcast::uri(it->first);
        tmp->type    = it->second;
        tmp->next    = NULL;
        tmp->next    = new hc_uri_list_t();
        tmp          = tmp->next;
    }
    delete (tmp->next);
    tmp->next = NULL;
    return res;
}

extern "C" void hc_init(hc_log_fun_t log_fun,
                        struct hc_module_handle* mod_handle,
                        hc_new_instance_callback_t new_instance_cb,
                        hc_recv_callback_t recv_cb,
                        hc_event_callback_t event_cb,
                        hc_atomic_msg_size_callback_t msg_size_cb,
                        size_t msg_size,
                        hc_kvp_list_t* kvp_list)
{
    // setup log function
    hc_set_log_fun(log_fun);
    HC_LOG_TRACE ("ip module init");
    // process kvp_list
    hc_kvp_list_t* kvp = kvp_list;
    discovery_ip_version ipv = IPALL;
    discovery_type sdt= OFF;
    string local_if;

    if (msg_size > IPM_DEFAULT_MSG_SIZE) {
        HC_LOG_FATAL ("MSG SIZE too large, max allowed message size: " << IPM_DEFAULT_MSG_SIZE);
        return;
    }

    /* extract config infos from kvp_list */
    while (kvp) {
        string key;
        std::transform(string(kvp->key).begin(),string(kvp->key).end(),key.begin(),toupper);
        string val;
        std::transform(string(kvp->value).begin(),string(kvp->value).end(),val.begin(),toupper);
        if (key == "DISCOVERY") {
            HC_LOG_DEBUG ("Key: " << key << " value: " << val);
            if (val == "FULL") {
                sdt = FULL;
            }
            else if (val == "LIGHT") {
                sdt = LIGHT;
            }
            else { // anything else means something like OFF
                sdt = OFF;
            }

        }
        else if ((key == "IPVERSION") || (key == "IP")) {
            HC_LOG_DEBUG ("Key: " << key << " value: " << val);
            if (val == "IP4") {
                ipv = IP4;
            }
            else if ( val == "IP6") {
                ipv = IP6;
            }
            else { // anything else means all IP versions
                ipv = IPALL;
            }
        }
        else if ((key == "INTERFACE") || (key == "IF") || (key == "IFACE")) {
            HC_LOG_DEBUG ("Key: " << key << " value: " << kvp->value);
            local_if = kvp->value;
        }
        kvp = kvp->next;
    }
    struct ifaddrs *ifaddrs = NULL;
    struct ifaddrs *ifa = NULL;
    int family, s;
    string iface_ip ("0.0.0.0");
    string iface_name ("unknown");
    unsigned int iface_index = 0;
    struct sockaddr_storage* iface_addr = NULL;
    
    if (getifaddrs(&ifaddrs) != 0) {
        HC_LOG_ERROR ("getifaddrs failed");
    }
    else {

        /* FIXME: this is crap, but we need it, thus its useful */
        for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL)
                continue;

            family = ifa->ifa_addr->sa_family;
            if (family == AF_INET) { // check it is IP4
                char ip_addr[NI_MAXHOST];
                s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                    ip_addr, sizeof(ip_addr), NULL, 0, NI_NUMERICHOST);
                if (s != 0) {
                    HC_LOG_ERROR("getnameinfo: " << gai_strerror(s));
                }
                else {
                    // is a valid IP4 Address
                    iface_addr = ((struct sockaddr_storage *)ifa->ifa_addr);
                    iface_ip = string(ip_addr);
                    iface_name = string(ifa->ifa_name);
                    iface_index = if_nametoindex(iface_name.c_str());
                    if ((iface_ip.find("127.0.0.1",0) == string::npos) && (iface_ip.find("127.0.1.1",0) == string::npos)) {
                        if (local_if.empty () || (iface_name.find (local_if,0) != string::npos)) {
                            break;
                        }
                    }
                }
            }
        }
    }

    ip_instance* _this = NULL;

    if (iface_addr != NULL) {
        HC_LOG_DEBUG ("Got iface info, ifname: " << iface_name << " ifindex: " << iface_index << ".");
        _this = new ip_instance(log_fun, event_cb, recv_cb, msg_size_cb, iface_index, iface_name, *iface_addr);
    }
    else {
        HC_LOG_DEBUG ("Got no iface info.");
        _this = new ip_instance(log_fun, event_cb, recv_cb, msg_size_cb);
    }

    std::string name_key = "if_name";
    std::string name_val = iface_name;
    std::string addr_key = "if_addr";
    std::string addr_val = "ip://";
    addr_val += iface_ip;
    std::string tech_key = "if_tech";
    std::string tech_val = "IPv4";

    hc_kvp_list_t name;
    name.key = name_key.c_str();
    name.value = name_val.c_str();
    name.next = 0;

    hc_kvp_list_t addr;
    addr.key = addr_key.c_str();
    addr.value = addr_val.c_str();
    addr.next = &name;

    hc_kvp_list_t tech;
    tech.key = tech_key.c_str();
    tech.value = tech_val.c_str();
    tech.next = &addr;

    hc_module_instance_handle_t hdl = new_instance_cb(_this, mod_handle, &tech,IPM_DEFAULT_MTU_SIZE);
    _this->set_handle(hdl);
    if (ifaddrs!=NULL)
        freeifaddrs(ifaddrs);
}

extern "C" int hc_join(hc_module_instance_t instance,
                       const hc_uri_t* group_uri,
                       const char*)
{
    return self(instance)->join(*group_uri);
}

extern "C" int hc_leave(hc_module_instance_t instance,
                        const hc_uri_t* group_uri,
                        const char*)
{
    return self(instance)->leave(*group_uri);
}

extern "C" int hc_sendto(hc_module_instance_t instance,
                         const void* buf,
                         int slen,
                         unsigned char ttl,
                         const hc_uri_t* group_uri,
                         const char*)
{
    return self(instance)->send(*group_uri, buf, slen, ttl);
}

extern "C" void hc_delete_instance(hc_module_instance_t instance)
{
    self(instance)->kill_receive_loop();
    delete self(instance);
}

extern "C" void hc_shutdown()
{
}

extern "C" hc_uri_result_t hc_map(hc_module_instance_t instance,
                                  const hc_uri_t* group_uri,
                                  const char*)
{
    return create_uri_result(self(instance)->map(*group_uri));
}

extern "C" hc_uri_list_t hc_neighbor_set(hc_module_instance_t instance)
{
    std::vector<hamcast::uri> result;
    self(instance)->neighbor_set(result);
    return create_uri_list(result);
}

extern "C" hc_uri_list_t hc_group_set(hc_module_instance_t instance)
{
    std::vector<std::pair<hamcast::uri, int> > result;
    self(instance)->group_set(result);
    return create_uri_list(result);
}

extern "C" hc_uri_list_t hc_children_set(hc_module_instance_t instance,
                                         const hc_uri_t* group_uri,
                                         const char*)
{
    std::vector<hamcast::uri> result;
    self(instance)->children_set(result, *group_uri);
    return create_uri_list(result);
}

extern "C" hc_uri_list_t hc_parent_set(hc_module_instance_t instance,
                                       const hc_uri_t* group_uri,
                                       const char*)
{
    std::vector<hamcast::uri> result;
    self(instance)->parent_set(result, *group_uri);
    return create_uri_list(result);
}

extern "C" int hc_designated_host(hc_module_instance_t instance,
                                  const hc_uri_t* group_uri,
                                  const char*)
{
    return self(instance)->designated_host(*group_uri);
}
