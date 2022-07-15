from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel

from textwrap import wrap
from datetime import date

import struct
import socket
import shutil
import glob
import os

from DataParser import DataParser


class UI:
    def __init__(self, parser: DataParser):
        self._parser = parser
        self.__console_columns = shutil.get_terminal_size().columns
        self.__save_file_name = self.__generate_save_file_name()
        self.__save_file = open(self.__save_file_name, "w")
        self.__save_file.close()
        self.__proto_count = {
            "udp": 0,
            "tcp": 0,
            "icmp": 0,
            "other": 0,
            "total": 0,
        }

    def __save_to_file(self, data):
        self.__save_file = open(self.__save_file_name, 'a')
        self.__save_file.write(data + '\n\n')
        self.__save_file.close()

    @staticmethod
    def __generate_save_file_name():
        d = date.today()
        cwd = os.getcwd()
        current_num = 0
        current_name = f"{cwd}/saves/{str(d)}({current_num}).txt"
        for name in glob.glob(cwd + "/saves/*.txt"):
            if name == current_name:
                current_num += 1
                current_name = f"{cwd}/saves/{str(d)}({current_num}).txt"
        return current_name

    @staticmethod
    def _format_mac_address(raw_mac):
        return ':'.join(map('{:02x}'.format, raw_mac)).upper()

    @staticmethod
    def _format_ip(ip):
        return '.'.join(map(str, ip))

    @staticmethod
    def _format_multi_line(prefix, string, size=60):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2 == 1:
                size -= 1
        else:
            raise TypeError

        return '\n'.join([prefix + line for line in wrap(string, size)])

    def parse_tcp(self, ipv4):
        try:
            tcp = self._parser.head_tcp(ipv4["data"])
        except struct.error as structErr:
            print(f"ERROR: {structErr}")
            return None

        body = "\t - TCP Segment:" \
               "\n\t\t - Source port: {}, Destination port: {}" \
               "\n\t\t - Sequence: {}, Acknowledgement: {}" \
               "\n\t\t - FLAGS:" \
               "\n\t\t\t - URG: {}, ACK: {}, PSH: {}" \
               "\n\t\t\t - RST: {}, SYN: {}, FIN: {}\n" \
            .format(tcp['src_port'], tcp['dest_port'], tcp['sequence'], tcp['ack'],
                    tcp['f_urg'], tcp['f_ack'], tcp['f_psh'],
                    tcp['f_rst'], tcp['f_syn'], tcp['f_fin'])

        try:
            if len(tcp[10]) > 0:
                # HTTP

                if tcp[0] == 80 or tcp[1] == 80:
                    body += "HTTP exchange data:\n"
                    try:
                        http = self._parser.head_http(tcp[10])
                        http_info = str(http[10]).split('\n')
                        for line in http_info:
                            body += "\t\t\t {}\n".format(line)
                    except TypeError:
                        body.__init__()
                        body += self._format_multi_line('\t\t\t', tcp[10])
                else:
                    body += "TCP data:\n"
                    body += self._format_multi_line('\t\t\t', tcp[10])
        except KeyError:
            pass

        return body

    def parse_icmp(self, ipv4):
        body = ""
        icmp = self._parser.head_icmp(ipv4["data"])
        body += "\t - ICMP Segment\n"
        body += "\t\tType: {}, Code: {}, Checksum: {}\n".format(icmp['type'], icmp['code'], icmp['checksum'])
        body += "\t\tICMP data:\n{}".format(self._format_multi_line('\t\t\t', icmp['data']))

        return body

    def parse_udp(self, ipv4):
        body = ""
        udp = self._parser.head_udp(ipv4["data"])
        body += "\t - UDP segment\n"
        body += "\t\tSource Port: {}, Destination Port: {}, Length: {}\n" \
            .format(udp['src_port'], udp['dest_port'], udp['size'])
        body += self._format_multi_line('\t\t\t', udp["data"])

        return body

    def run(self):
        # init
        soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        console = Console()
        layout = Layout()
        layout.split_column(
            Layout(name="header"),
            Layout(name="main", ratio=2)
        )

        layout["main"].split_row(
            Layout(name="side"),
            Layout(name="body", ratio=2)
        )

        header = "\n\n{}\n{}\n\n\nQuick commands:\nCtrl+C -> exit the application\n" \
            .format("Packet sniffer".center(self.__console_columns),
                    "by Andrei-Fabian Pop".center(self.__console_columns + 2 * len("by Andrei-Fabian Pop")))

        layout["header"].update(Panel(header, border_style="green"))

        # loop start
        try:
            while True:
                raw_data, addr = soc.recvfrom(65565)
                eth = self._parser.parse_header(raw_data)

                body = "Internet Layer:\nDestination: {}, Source: {}, Protocol: {}\n" \
                    .format(self._format_mac_address(eth["dest_mac"]),
                            self._format_mac_address(eth["src_mac"]),
                            eth["protocol"])
                side = "Packet count:\n"

                if eth["protocol"] == 8:
                    ipv4 = self._parser.head_ipv4(eth["data"])

                    body += "\tData frame:\n\t\t - Version: {}, Header Length: {}, Time To Live: {}" \
                            "\n\t\t - Protocol: {}, Source: {}, Target: {}\n" \
                        .format(ipv4['version'], ipv4['len'], ipv4['ttl'], ipv4['protocol'],
                                self._format_ip(ipv4['src']),
                                self._format_ip(ipv4['target']))

                    # TCP
                    if ipv4["protocol"] == 6:
                        self.__proto_count["tcp"] += 1
                        body += self.parse_tcp(ipv4)

                    # ICMP
                    elif ipv4["protocol"] == 1:
                        self.__proto_count["icmp"] += 1
                        body += self.parse_icmp(ipv4)

                    # UDP
                    elif ipv4["protocol"] == 17:
                        self.__proto_count["udp"] += 1
                        body += self.parse_udp(ipv4)
                    else:
                        self.__proto_count["other"] += 1

                    side += \
                        "TOTAL: {}\n" \
                        "TCP: {}\n" \
                        "UDP: {}\n" \
                        "ICMP: {}\n" \
                        "Other: {}\n".format(
                            self.__proto_count["total"],
                            self.__proto_count["tcp"],
                            self.__proto_count["udp"],
                            self.__proto_count["icmp"],
                            self.__proto_count["other"]
                        )

                    self.__save_to_file(body)
                    layout["body"].update(Panel(body, border_style="green"))
                    layout["side"].update(Panel(side, border_style="green"))
                    console.print(layout)
        except KeyboardInterrupt:
            layout["header"].update("\nGoodbye...")
            console.print(layout)
