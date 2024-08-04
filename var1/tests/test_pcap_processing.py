import pytest
import tempfile
from scapy.all import wrpcap #, Ether, IP, TCP
from scapy.layers.inet import Ether, IP, TCP

from pcap_processing import extract_packets, find_matching_intervals, main


# Функция для создания тестовых pcap файлов
def create_test_pcap(packets, filename):
    wrpcap(filename, packets)


# Создание временных pcap файлов для тестов
@pytest.fixture
def pcap_files():
    # Создание временных файлов
    temp_file1 = tempfile.NamedTemporaryFile(delete=False)
    temp_file2 = tempfile.NamedTemporaryFile(delete=False)

    # Создание пакетов для первого pcap файла
    packets1 = [
        Ether() / IP(dst="1.1.1.1") / TCP(dport=80),
        Ether() / IP(dst="2.2.2.2") / TCP(dport=80),
        Ether() / IP(dst="3.3.3.3") / TCP(dport=80),
        Ether() / IP(dst="4.4.4.4") / TCP(dport=80),
    ]

    # Создание пакетов для второго pcap файла
    packets2 = [
        Ether() / IP(dst="3.3.3.3") / TCP(dport=80),
        Ether() / IP(dst="4.4.4.4") / TCP(dport=80),
        Ether() / IP(dst="5.5.5.5") / TCP(dport=80),
    ]

    # Запись пакетов в pcap файлы
    create_test_pcap(packets1, temp_file1.name)
    create_test_pcap(packets2, temp_file2.name)

    yield temp_file1.name, temp_file2.name

    # Удаление временных файлов после тестов
    temp_file1.close()
    temp_file2.close()


# Тестирование функции extract_packets
def test_extract_packets(pcap_files):
    pcap_file1, pcap_file2 = pcap_files
    packets1 = extract_packets(pcap_file1)
    packets2 = extract_packets(pcap_file2)

    assert len(packets1) == 4
    assert len(packets2) == 3


# Тестирование функции find_matching_intervals
def test_find_matching_intervals():
    seq1 = [("A", 0), ("B", 1), ("C", 2), ("D", 3)]
    seq2 = [("C", 2), ("D", 3), ("E", 4)]
    min_match_length = 1

    intervals = find_matching_intervals(seq1, seq2, min_match_length)

    assert len(intervals) == 1
    assert intervals[0] == (2, 0, 2, 2, 2)


# Тестирование функции main
def test_main(pcap_files, capsys):
    pcap_file1, pcap_file2 = pcap_files
    min_match_length = 1
    interval_nums = [0]

    main(pcap_file1, pcap_file2, min_match_length, interval_nums)

    captured = capsys.readouterr()

    assert "Total matching intervals: 1" in captured.out
    assert "Interval 1:" in captured.out
    assert "Matching length: 2" in captured.out
