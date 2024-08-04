from scapy.all import rdpcap


def extract_packets(pcap_file):
    packets = rdpcap(pcap_file)
    packet_summaries = [(pkt.summary(), pkt.time) for pkt in packets]
    return packet_summaries


def find_matching_intervals(seq1, seq2, min_match_length):
    m, n = len(seq1), len(seq2)
    table = [[0] * n for _ in range(m)]
    intervals = []

    # Поиск всех максимальных подпоследовательностей
    for i in range(m):
        for j in range(n):
            if seq1[i][0] == seq2[j][0]:
                if i == 0 or j == 0:
                    table[i][j] = 1
                else:
                    table[i][j] = table[i - 1][j - 1] + 1

                if table[i][j] >= min_match_length:
                    start_i = i - table[i][j] + 1
                    start_j = j - table[i][j] + 1
                    length = table[i][j]
                    intervals.append((start_i, start_j, length, seq1[start_i][1], seq2[start_j][1]))
            else:
                table[i][j] = 0

    # Сортировка интервалов по длине в убывающем порядке
    intervals.sort(key=lambda x: x[2], reverse=True)

    # Фильтрация интервалов, убираем те, которые полностью входят в другие
    filtered_intervals = []

    for interval in intervals:
        start_i, start_j, length, _, _ = interval
        is_subset = False

        # Проверяем, не является ли текущий интервал полностью вложенным в уже найденные интервалы
        for existing in filtered_intervals:
            existing_start_i, existing_start_j, existing_length, _, _ = existing
            if (start_i >= existing_start_i and start_i + length <= existing_start_i + existing_length and
                    start_j >= existing_start_j and start_j + length <= existing_start_j + existing_length):
                is_subset = True
                break

        if not is_subset:
            filtered_intervals.append(interval)

    return filtered_intervals


def main(pcap_file1, pcap_file2, min_match_length, interval_nums):
    # Извлечение пакетов
    packets1 = extract_packets(pcap_file1)
    packets2 = extract_packets(pcap_file2)

    # Поиск совпадающих интервалов
    intervals = find_matching_intervals(packets1, packets2, min_match_length)

    # Вывод результатов
    print(f"Total matching intervals: {len(intervals)}")
    if interval_nums is None:
        interval_nums = range(len(intervals))

    for index in interval_nums:
        if index < len(intervals):
            start_i, start_j, match_length, time_stamp_1, time_stamp_2 = intervals[index]
            print(f"Interval {index + 1}:")
            print(f"  Matching length: {match_length}")
            print(f"  pcap file 1. Start index: {start_i},  Time_stamp: {time_stamp_1}")
            print(f"  pcap file 2. Start index: {start_j},  Time_stamp: {time_stamp_2}")
        else:
            print(f"Interval {index + 1} does not exist.")


# Пример использования
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Find matching intervals in two pcap files.")
    parser.add_argument("pcap_file1", help="Path to the first pcap file")
    parser.add_argument("pcap_file2", help="Path to the second pcap file")
    parser.add_argument("--min_length", type=int, default=1, help="Minimum length of matching packets")
    parser.add_argument("--intervals", type=int, nargs='*', default=[0],
                        help="List of interval numbers to display (default is the first interval)")
    args = parser.parse_args()

    main(args.pcap_file1, args.pcap_file2, args.min_length, args.intervals)
