import dpkt
from datetime import *
import socket


class Datagram:
    id = 0
    seq_num = 0
    time_tag = 0
    packet = None


def convert_in_list(file_name):
    convert_list = []
    out_set = set()
    in_dict = {}
    with open(file_name, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for j, buf in enumerate(pcap):
            try:
                packet = dpkt.ethernet.Ethernet(buf[1])
                datagram = Datagram()
                datagram.id = packet.ip.id
                datagram.time_tag = datetime.fromtimestamp(int(buf[0])).strftime('%H:%M')
                datagram.seq_num = j
                datagram.packet = packet
                if file_name == input_file:
                    in_dict[datagram.id] = datagram.seq_num
                    convert_list.append(datagram)
                else:
                    if datagram.id in out_set:
                        datagram.id = '-1'
                        convert_list.append(datagram)
                    else:
                        convert_list.append(datagram)
                        out_set.add(datagram.id)
            except:
                pass
    return [convert_list, in_dict]


def get_intervals(input_list, output_list):
    in_list = input_list[0]
    in_dict = input_list[1]
    out_list = output_list[0]
    i = 0
    dict_key = 1
    res_dict = {}
    res_dict[dict_key] = []
    out_list_index = 0
    in_list_index = 0
    while i < len(out_list):
        if out_list_index >= len(out_list) - 1 or in_list_index >= len(in_list) - 1:
            i += 1
        else:
            try:
                in_list_index = in_dict[out_list[i].id]
                out_list_index = i
                res_dict[dict_key].append(out_list[out_list_index])
                while out_list_index < len(out_list) - 1 and in_list_index < len(in_list) - 1:
                    out_list_index += 1
                    in_list_index += 1
                    i = out_list_index
                    if out_list[out_list_index].id == in_list[in_list_index].id:
                        res_dict[dict_key].append(out_list[out_list_index])
                    else:
                        dict_key += 1
                        res_dict[dict_key] = []
                        break
            except:
                i += 1
                pass

    return res_dict


def print_rng_qnt(intv_dict):
    ranges_count = 0
    for key, value in intv_dict.items():
        if len(value) >= interval_len:
            ranges_count += 1
    print(f"Количество совпадающих интервалов: {ranges_count}")
    return ranges_count


def print_pack_qnt(intv_dict, input_list):
    range_num = 1
    ranges_dict = {}
    in_list = input_list[0]
    in_dict = input_list[1]
    for key, value in intv_dict.items():
        if len(value) >= interval_len:
            print(f"Количество совпаших пакетов: {len(value)} для интервала: {range_num}")
            ranges_dict[range_num] = value
            range_num += 1
    for key, value in ranges_dict.items():
        if key == interval_num:
            list_index = in_dict[value[0].id]
            packet = in_list[list_index]
            print(
                f"Номер первого пакета: {value[0].seq_num}, метка времени: {value[0].time_tag} для файла: {output_file}")
            print(f"Номер первого пакета: {packet.seq_num}, метка времени: {packet.time_tag} для файла: {input_file}")
            break


def create_ip_packet(src_ip, dst_ip, id_num, proto=dpkt.ip.IP_PROTO_UDP):
    ip = dpkt.ip.IP()
    ip.src = socket.inet_aton(src_ip)
    ip.dst = socket.inet_aton(dst_ip)
    ip.id = int(id_num)
    ip.p = proto
    ip.data = b'Hello, World!'
    ip.len = len(ip)
    ip.ttl = 64
    return ip


def generate_ip_packets(id_arr):
    ip_packets = []
    src_ip = '192.168.1.111'
    dst_ip = '192.168.1.222'

    for pack_id in id_arr:
        ip_packet = create_ip_packet(src_ip, dst_ip, pack_id)
        ip_packets.append(ip_packet)
    return ip_packets


# Раскомментировать при запуске без pytest
if __name__ == "__main__":
    input_file = str(input("Введите название файла для точки А: "))
    output_file = str(input("Введите название файла для точки B: "))
    interval_len = int(input("Введите длину интервала: "))
    interval_num = int(input("Введите номер интервала: "))

    in_arr = convert_in_list(input_file)
    final_dict = get_intervals(in_arr, convert_in_list(output_file))
    print_rng_qnt(final_dict)
    print_pack_qnt(final_dict, in_arr)
else:
    input_file = None
    output_file = None
    interval_len = 0
    interval_num= 0