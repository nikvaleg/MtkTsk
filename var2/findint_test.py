# pytest

import dpkt
import socket

from find_intervals import *

def test_print_rng_qnt():
    id_nums_A = [1, 2, 3, 4, 5, 6]
    dict_A = {1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5}
    id_nums_B = [1, 2, 3, 5, 6]
    dict_B = dict()
    id_nums_B = [1, 2, 3, 5, 6]
    final_dict = get_intervals([generate_ip_packets(id_nums_A), dict_A], [generate_ip_packets(id_nums_B), dict_B])
    assert print_rng_qnt(final_dict)== 2

